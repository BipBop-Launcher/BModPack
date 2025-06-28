#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <curl/curl.h>
#include <archive.h>
#include <archive_entry.h>
#include <zlib.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    char *memory;
    size_t size;
} Memory;

static size_t write_callback(void *data, size_t sz, size_t nmemb, void *userp) {
    size_t total = sz * nmemb;
    Memory *mem = userp;
    char *newbuf = realloc(mem->memory, mem->size + total + 1);
    if (!newbuf) {
        fprintf(stderr, "realloc failed\n");
        return 0;
    }
    mem->memory = newbuf;
    memcpy(mem->memory + mem->size, data, total);
    mem->size += total;
    mem->memory[mem->size] = '\0';
    return total;
}

EVP_PKEY *fetch_public_key(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "CURL init failed\n");
        return NULL;
    }

    Memory chunk = { .memory = malloc(1), .size = 0 };
    if (!chunk.memory) {
        fprintf(stderr, "malloc failure\n");
        curl_easy_cleanup(curl);
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        free(chunk.memory);
        curl_easy_cleanup(curl);
        return NULL;
    }
    curl_easy_cleanup(curl);

    BIO *bio = BIO_new_mem_buf(chunk.memory, (int)chunk.size);
    if (!bio) {
        fprintf(stderr, "BIO_new_mem_buf failed\n");
        free(chunk.memory);
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(chunk.memory);

    if (!pkey) {
        fprintf(stderr, "PEM_read_bio_PUBKEY failed\n");
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
    int ret = -1;
    FILE *in = fopen(inpath, "rb");
    if (!in) {
        perror("fopen input");
        return -1;
    }
    if (fseek(in, 0, SEEK_END) < 0) { perror("fseek"); goto cleanup_in; }
    long inlen = ftell(in);
    rewind(in);

    unsigned char *inbuf = malloc(inlen);
    if (!inbuf) { fprintf(stderr, "malloc inbuf\n"); goto cleanup_in; }
    if (fread(inbuf, 1, inlen, in) != (size_t)inlen) {
        fprintf(stderr, "fread error\n");
        goto cleanup_inbuf;
    }
    fclose(in);
    in = NULL;

    if (RAND_bytes(iv, 12) != 1) {
        fprintf(stderr, "RAND_bytes IV failed\n");
        goto cleanup_inbuf;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { fprintf(stderr, "EVP_CIPHER_CTX_new failed\n"); goto cleanup_inbuf; }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n"); goto cleanup_ctx;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl IV length failed\n"); goto cleanup_ctx;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex key/iv failed\n"); goto cleanup_ctx;
    }

    *out = malloc(inlen + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    if (!*out) { fprintf(stderr, "malloc ciphertext\n"); goto cleanup_ctx; }

    int len, tmplen;
    if (EVP_EncryptUpdate(ctx, *out, &len, inbuf, inlen) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n"); goto cleanup_outbuf;
    }
    *outlen = len;

    if (EVP_EncryptFinal_ex(ctx, *out + len, &tmplen) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n"); goto cleanup_outbuf;
    }
    *outlen += tmplen;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_GET_TAG failed\n"); goto cleanup_outbuf;
    }

    FILE *outf = fopen(outpath, "wb");
    if (!outf) { perror("fopen output"); goto cleanup_outbuf; }
    if (fwrite(iv, 1, 12, outf) != 12 ||
        fwrite(*out, 1, *outlen, outf) != (size_t)*outlen ||
        fwrite(tag, 1, 16, outf) != 16) {
        fprintf(stderr, "fwrite failed\n");
        fclose(outf);
        goto cleanup_outbuf;
    }
    fclose(outf);
    ret = 0;

cleanup_outbuf:
    if (ret && *out) { free(*out); *out = NULL; }
cleanup_ctx:
    EVP_CIPHER_CTX_free(ctx);
cleanup_inbuf:
    free(inbuf);
cleanup_in:
    if (in) fclose(in);
    return ret;
}

int create_tar_gz(const char *srcdir, const char *outpath) {
    struct archive *a = archive_write_new();
    if (!a) return -1;
    archive_write_set_format_pax_restricted(a);
    archive_write_add_filter_gzip(a);
    if (archive_write_open_filename(a, outpath) != ARCHIVE_OK) {
        fprintf(stderr, "archive open: %s\n", archive_error_string(a));
        archive_write_free(a);
        return -1;
    }

    struct archive *disk = archive_read_disk_new();
    archive_read_disk_set_standard_lookup(disk);

    struct {
        char path[PATH_MAX];
        char prefix[PATH_MAX];
        DIR *dir;
    } stack[100];
    int top = 0;
    if (strlen(srcdir) >= PATH_MAX) {
        fprintf(stderr, "srcdir path too long\n");
        goto cleanup;
    }
    strcpy(stack[0].path, srcdir);
    stack[0].prefix[0] = '\0';
    stack[0].dir = opendir(srcdir);
    if (!stack[0].dir) {
        perror("opendir srcdir");
        goto cleanup;
    }

    while (top >= 0) {
        DIR *d = stack[top].dir;
        struct dirent *de = readdir(d);
        if (!de) {
            closedir(d);
            top--;
            continue;
        }
        if (strcmp(de->d_name, ".")==0 || strcmp(de->d_name, "..")==0)
            continue;

        char full[PATH_MAX], arcname[PATH_MAX];
        if (snprintf(full, PATH_MAX, "%s/%s", stack[top].path, de->d_name) >= PATH_MAX) {
            fprintf(stderr, "path overflow\n");
            continue;
        }
        if (stack[top].prefix[0]) {
            snprintf(arcname, PATH_MAX, "%s/%s", stack[top].prefix, de->d_name);
        } else {
            strncpy(arcname, de->d_name, PATH_MAX-1);
            arcname[PATH_MAX-1] = '\0';
        }

        struct stat st;
        if (stat(full, &st) != 0) {
            perror("stat");
            continue;
        }

        struct archive_entry *entry = archive_entry_new();
        archive_entry_set_pathname(entry, arcname);
        archive_entry_copy_stat(entry, &st);
        if (archive_write_header(a, entry) != ARCHIVE_OK) {
            fprintf(stderr, "archive_write_header: %s\n", archive_error_string(a));
            archive_entry_free(entry);
            goto cleanup;
        }

        if (S_ISREG(st.st_mode)) {
            FILE *f = fopen(full, "rb");
            if (f) {
                char buf[8192];
                size_t r;
                while ((r = fread(buf,1,sizeof(buf),f))>0)
                    archive_write_data(a, buf, r);
                fclose(f);
            }
        } else if (S_ISDIR(st.st_mode) && top < 99) {
            top++;
            strcpy(stack[top].path, full);
            strcpy(stack[top].prefix, arcname);
            stack[top].dir = opendir(full);
            if (!stack[top].dir) {
                perror("opendir");
                top--;
            }
        }
        archive_entry_free(entry);
    }

cleanup:
    archive_read_free(disk);
    archive_write_close(a);
    archive_write_free(a);
    return 0;
}

static void cleanup_tmp(const char *tmpdir) {
    char path[PATH_MAX];

    snprintf(path, PATH_MAX, "%s/metadata.tar.gz", tmpdir);
    unlink(path);
    snprintf(path, PATH_MAX, "%s/code.tar.gz",    tmpdir);
    unlink(path);
    snprintf(path, PATH_MAX, "%s/code.enc",        tmpdir);
    unlink(path);

    snprintf(path, PATH_MAX, "%s/metadata", tmpdir);
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                continue;
            char child[PATH_MAX];
            if (snprintf(child, PATH_MAX, "%s/%s", path, ent->d_name) >= PATH_MAX) {
                fprintf(stderr, "cleanup_tmp: path too long: %s/%s\n", path, ent->d_name);
                continue;
            }
            if (unlink(child) < 0) {
                perror("cleanup_tmp: unlink");
            }
        }
        closedir(d);
    } else {
        if (errno != ENOENT) perror("cleanup_tmp: opendir metadata");
    }

    if (rmdir(path) < 0 && errno != ENOENT) {
        perror("cleanup_tmp: rmdir metadata");
    }
    if (rmdir(tmpdir) < 0) {
        perror("cleanup_tmp: rmdir tmpdir");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <mod_folder_path>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *mod_path = argv[1];
    struct stat st;
    if (stat(mod_path, &st)<0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: invalid path\n");
        return EXIT_FAILURE;
    }

    char cfg[PATH_MAX];
    snprintf(cfg, PATH_MAX, "%s/mod.cfg", mod_path);
    if (stat(cfg, &st)<0) {
        fprintf(stderr, "mod.cfg missing\n");
        return EXIT_FAILURE;
    }

    printf("Fetching RSA public key...\n");
    EVP_PKEY *pkey = fetch_public_key("https://bipbop.bopimod.com/encrypt.pub");
    if (!pkey) return EXIT_FAILURE;

    char tmpdir[] = "/tmp/modpackXXXXXX";
    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        EVP_PKEY_free(pkey);
        return EXIT_FAILURE;
    }
    char metadata_dir[PATH_MAX];
    snprintf(metadata_dir, PATH_MAX, "%s/metadata", tmpdir);
    if (mkdir(metadata_dir,0755)<0) {
        perror("mkdir metadata");
        EVP_PKEY_free(pkey);
        cleanup_tmp(tmpdir);
        return EXIT_FAILURE;
    }

    const char *meta[] = { "icon.png", "mod.cfg" };
    for (int i = 0; i < 2; i++) {
        char src[PATH_MAX], dst[PATH_MAX];
        snprintf(src, PATH_MAX, "%s/%s", mod_path, meta[i]);
        snprintf(dst, PATH_MAX, "%s/%s", metadata_dir, meta[i]);
        FILE *in = fopen(src, "rb");
        if (!in) continue;
        FILE *out = fopen(dst, "wb");
        if (!out) { fclose(in); continue; }
        char buf[8192];
        size_t n;
        while ((n = fread(buf,1,sizeof(buf),in)) > 0)
            fwrite(buf,1,n,out);
        fclose(in);
        fclose(out);
    }

    char meta_tgz[PATH_MAX], code_tgz[PATH_MAX];
    snprintf(meta_tgz, PATH_MAX, "%s/metadata.tar.gz", tmpdir);
    snprintf(code_tgz, PATH_MAX, "%s/code.tar.gz", tmpdir);
    if (create_tar_gz(metadata_dir, meta_tgz) ||
        create_tar_gz(mod_path,   code_tgz)) {
        fprintf(stderr, "Failed to create archives\n");
        EVP_PKEY_free(pkey);
        cleanup_tmp(tmpdir);
        return EXIT_FAILURE;
    }

    unsigned char aes_key[32], iv[12];
    if (RAND_bytes(aes_key,sizeof(aes_key)) != 1) {
        fprintf(stderr, "RAND_bytes key failed\n");
        EVP_PKEY_free(pkey);
        cleanup_tmp(tmpdir);
        return EXIT_FAILURE;
    }

    unsigned char *ciphertext = NULL;
    int cipherlen = 0;
    char enc_path[PATH_MAX];
    snprintf(enc_path, PATH_MAX, "%s/code.enc", tmpdir);
    if (encrypt_file_aes(code_tgz, enc_path, aes_key, iv, &ciphertext, &cipherlen)) {
        fprintf(stderr, "AES encryption failed\n");
        EVP_PKEY_free(pkey);
        cleanup_tmp(tmpdir);
        return EXIT_FAILURE;
    }

    // RSA-OAEP wrap
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx ||
        EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fprintf(stderr, "RSA ctx init failed\n");
        EVP_PKEY_free(pkey);
        cleanup_tmp(tmpdir);
        return EXIT_FAILURE;
    }
    size_t eklen = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &eklen, aes_key, sizeof(aes_key)) <= 0) {
        fprintf(stderr, "RSA encrypt size prep failed\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        cleanup_tmp(tmpdir);
        return EXIT_FAILURE;
    }
    unsigned char *encrypted_key = malloc(eklen);
    if (!encrypted_key ||
        EVP_PKEY_encrypt(ctx, encrypted_key, &eklen, aes_key, sizeof(aes_key)) <= 0) {
        fprintf(stderr, "RSA encrypt failed\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        free(encrypted_key);
        cleanup_tmp(tmpdir);
        return EXIT_FAILURE;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    const char *base = strrchr(mod_path, '/');
    if (base) base++;
    else      base = mod_path;
    char outfn[PATH_MAX];
    snprintf(outfn, PATH_MAX, "%s.bmod", base);

    FILE *out = fopen(outfn, "wb");
    if (!out) {
        perror("fopen output bmod");
        free(encrypted_key);
        free(ciphertext);
        cleanup_tmp(tmpdir);
        return EXIT_FAILURE;
    }
    fwrite("BMOD",1,4,out);
    unsigned char ver = 1;
    fwrite(&ver,1,1,out);

    unsigned short klen_n = htons((unsigned short)eklen);
    fwrite(&klen_n,2,1,out);
    fwrite(encrypted_key,1,eklen,out);

    FILE *mf = fopen(meta_tgz,"rb");
    if (!mf) { fclose(out); perror("fopen meta_tgz"); return EXIT_FAILURE; }
    fseek(mf,0,SEEK_END);
    unsigned int msz = htonl((unsigned int)ftell(mf));
    rewind(mf);
    fwrite(&msz,4,1,out);
    char buf[8192];
    size_t r;
    while ((r = fread(buf,1,sizeof(buf),mf))>0)
        fwrite(buf,1,r,out);
    fclose(mf);

    FILE *ef = fopen(enc_path,"rb");
    if (!ef) { fclose(out); perror("fopen enc_path"); return EXIT_FAILURE; }
    while ((r = fread(buf,1,sizeof(buf),ef))>0)
        fwrite(buf,1,r,out);
    fclose(ef);
    fclose(out);

    printf("Mod packed to %s\n", outfn);

    free(encrypted_key);
    free(ciphertext);
    cleanup_tmp(tmpdir);
    return EXIT_SUCCESS;
}
