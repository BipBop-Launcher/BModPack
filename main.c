#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <curl/curl.h>
#include <archive.h>
#include <archive_entry.h>
#include <zlib.h>

typedef struct {
    char *name;
    char *version;
    char *description;
    char *author;
} ModMetadata;

struct Memory {
    char *memory;
    size_t size;
};

static size_t write_callback(void *data, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    struct Memory *mem = (struct Memory *)userp;
    char *ptr = realloc(mem->memory, mem->size + total + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(mem->memory + mem->size, data, total);
    mem->size += total;
    mem->memory[mem->size] = '\0';
    return total;
}

// Fetch PEM public key
EVP_PKEY *fetch_public_key(const char *url) {
    CURL *curl = curl_easy_init();
    struct Memory chunk = { malloc(1), 0 };
    if (!curl) {
        fprintf(stderr, "CURL init failed\n");
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    if (curl_easy_perform(curl) != CURLE_OK) {
        fprintf(stderr, "Failed to fetch key: %s\n",
                curl_easy_strerror(curl_easy_perform(curl)));
        free(chunk.memory);
        curl_easy_cleanup(curl);
        return NULL;
    }
    curl_easy_cleanup(curl);

    BIO *bio = BIO_new_mem_buf(chunk.memory, chunk.size);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(chunk.memory);

    if (!pkey) {
        fprintf(stderr, "Failed to parse public key\n");
        ERR_print_errors_fp(stderr);
    }
    return pkey;
}

// AES-GCM encryption
int encrypt_file_aes(const char *inpath,
                     const char *outpath,
                     unsigned char *key,
                     unsigned char *iv,
                     unsigned char **out,
                     int *outlen)
{
    FILE *in = fopen(inpath, "rb");
    if (!in) return -1;
    fseek(in, 0, SEEK_END);
    long inlen = ftell(in);
    fseek(in, 0, SEEK_SET);

    unsigned char *inbuf = malloc(inlen);
    fread(inbuf, 1, inlen, in);
    fclose(in);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    int len;
    *out = malloc(inlen + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    EVP_EncryptUpdate(ctx, *out, &len, inbuf, inlen);
    *outlen = len;
    EVP_EncryptFinal_ex(ctx, *out + len, &len);
    *outlen += len;

    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    FILE *outf = fopen(outpath, "wb");
    fwrite(iv, 1, 12, outf);
    fwrite(*out, 1, *outlen, outf);
    fwrite(tag, 1, 16, outf);
    fclose(outf);

    EVP_CIPHER_CTX_free(ctx);
    free(inbuf);
    return 0;
}

int create_tar_gz(const char *srcdir, const char *outpath) {
    struct archive *a = archive_write_new();
    archive_write_set_format_pax_restricted(a);
    archive_write_add_filter_gzip(a);
    archive_write_open_filename(a, outpath);

    struct archive *disk = archive_read_disk_new();
    archive_read_disk_set_standard_lookup(disk);

    DIR *dir = opendir(srcdir);
    if (!dir) return -1;

    struct dirent *de;
    while ((de = readdir(dir))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", srcdir, de->d_name);

        struct stat st;
        stat(fullpath, &st);

        struct archive_entry *entry = archive_entry_new();
        archive_entry_set_pathname(entry, de->d_name);
        archive_entry_copy_stat(entry, &st);
        archive_write_header(a, entry);

        if (S_ISREG(st.st_mode)) {
            FILE *f = fopen(fullpath, "rb");
            unsigned char buff[8192];
            int r;
            while ((r = fread(buff, 1, sizeof(buff), f)) > 0)
                archive_write_data(a, buff, r);
            fclose(f);
        }
        archive_entry_free(entry);
    }

    closedir(dir);
    archive_read_free(disk);
    archive_write_close(a);
    archive_write_free(a);
    return 0;
}

int main(int argc, char *argv[]) {
    unsigned char buf[8192];
    size_t cipherlen;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <mod_folder_path>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *mod_path = argv[1];
    struct stat st;
    if (stat(mod_path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: invalid path\n");
        return EXIT_FAILURE;
    }

    char cfg_path[1024];
    snprintf(cfg_path, sizeof(cfg_path), "%s/mod.cfg", mod_path);
    if (stat(cfg_path, &st) < 0) {
        fprintf(stderr, "mod.cfg missing\n");
        return EXIT_FAILURE;
    }

    printf("Fetching RSA public key...\n");
    EVP_PKEY *pkey = fetch_public_key("https://bipbop.bopimod.com/encrypt.pub");
    if (!pkey) return EXIT_FAILURE;

    char *tmpdir = strdup("/tmp/modpackXXXXXX");
    mkdtemp(tmpdir);
    char metadata_dir[1024];
    snprintf(metadata_dir, sizeof(metadata_dir), "%s/metadata", tmpdir);
    mkdir(metadata_dir, 0755);

    const char *meta_files[] = { "icon.png", "mod.cfg" };
    for (int i = 0; i < 2; i++) {
        char src[1024], dst[1024];
        snprintf(src, sizeof(src), "%s/%s", mod_path, meta_files[i]);
        snprintf(dst, sizeof(dst), "%s/%s", metadata_dir, meta_files[i]);
        if (stat(src, &st) == 0) {
            FILE *s = fopen(src, "rb");
            FILE *d = fopen(dst, "wb");
            int r;
            while ((r = fread(buf, 1, sizeof(buf), s)) > 0)
                fwrite(buf, 1, r, d);
            fclose(s);
            fclose(d);
        }
    }

    char metadata_tgz[1024], code_tgz[1024];
    snprintf(metadata_tgz, sizeof(metadata_tgz), "%s/metadata.tar.gz", tmpdir);
    snprintf(code_tgz, sizeof(code_tgz), "%s/code.tar.gz", tmpdir);
    create_tar_gz(metadata_dir, metadata_tgz);
    create_tar_gz(mod_path, code_tgz);

    // Generate AES key & IV
    unsigned char aes_key[32], iv[12];
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(iv, sizeof(iv));

    unsigned char *ciphertext;
    int ciphertext_len;
    char enc_path[1024];
    snprintf(enc_path, sizeof(enc_path), "%s/code.enc", tmpdir);
    encrypt_file_aes(code_tgz, enc_path, aes_key, iv,
                     &ciphertext, &ciphertext_len);

    // RSA-wrap AES key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    size_t eklen;
    EVP_PKEY_encrypt(ctx, NULL, &eklen, aes_key, sizeof(aes_key));
    unsigned char *encrypted_key = malloc(eklen);
    EVP_PKEY_encrypt(ctx, encrypted_key, &eklen, aes_key, sizeof(aes_key));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    char outpath[1024];
    snprintf(outpath, sizeof(outpath), "%s.bmod",
             strrchr(mod_path, '/') + 1);
    FILE *out = fopen(outpath, "wb");

    fwrite("BMOD", 1, 4, out);
    unsigned char ver = 1;
    fwrite(&ver, 1, 1, out);

    unsigned short klen = htons((unsigned short)eklen);
    fwrite(&klen, 2, 1, out);
    fwrite(encrypted_key, 1, eklen, out);

    FILE *metaf = fopen(metadata_tgz, "rb");
    fseek(metaf, 0, SEEK_END);
    unsigned int msize = htonl((unsigned int)ftell(metaf));
    fseek(metaf, 0, SEEK_SET);
    fwrite(&msize, 4, 1, out);
    while ((cipherlen = fread(buf, 1, sizeof(buf), metaf)) > 0)
        fwrite(buf, 1, cipherlen, out);
    fclose(metaf);

    FILE *encf = fopen(enc_path, "rb");
    while ((cipherlen = fread(buf, 1, sizeof(buf), encf)) > 0)
        fwrite(buf, 1, cipherlen, out);
    fclose(encf);
    fclose(out);

    printf("Mod packed to %s\n", outpath);

    free(tmpdir);
    free(ciphertext);
    free(encrypted_key);
    return EXIT_SUCCESS;
}
