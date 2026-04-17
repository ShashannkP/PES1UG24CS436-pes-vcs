// object.c — Content-addressable object store

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTATION ──────────────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {

    // 1. Determine type string
    const char *type_str = (type == OBJ_BLOB) ? "blob" :
                           (type == OBJ_TREE) ? "tree" : "commit";

    // 2. Build header
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);

    // 3. Build full object = header + '\0' + data
    size_t total_len = header_len + 1 + len;
    uint8_t *buffer = malloc(total_len);
    if (!buffer) return -1;

    memcpy(buffer, header, header_len);
    buffer[header_len] = '\0';
    memcpy(buffer + header_len + 1, data, len);

    // 4. Compute hash
    compute_hash(buffer, total_len, id_out);

    // 5. Deduplication check
    if (object_exists(id_out)) {
        free(buffer);
        return 0;
    }

    // 6. Get final path
    char path[512];
    object_path(id_out, path, sizeof(path));

    // Extract directory path
    char dir[512];
    strcpy(dir, path);
    char *slash = strrchr(dir, '/');
    if (!slash) {
        free(buffer);
        return -1;
    }
    *slash = '\0';

    // 7. Create directories
    mkdir(OBJECTS_DIR, 0755);  // ignore error if exists
    mkdir(dir, 0755);

    // 8. Temp file path
    char tmp_path[520];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    // 9. Write temp file
    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(buffer);
        return -1;
    }

    if (write(fd, buffer, total_len) != (ssize_t)total_len) {
        close(fd);
        free(buffer);
        return -1;
    }

    // 10. fsync file
    fsync(fd);
    close(fd);

    // 11. Rename (atomic)
    if (rename(tmp_path, path) != 0) {
        free(buffer);
        return -1;
    }

    // 12. fsync directory
    int dir_fd = open(dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(buffer);
    return 0;
}

// ────────────────────────────────────────────────────────────────────────────

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {

    // 1. Build path
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // 3. Read entire file
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    rewind(f);

    uint8_t *buffer = malloc(file_size);
    if (!buffer) {
        fclose(f);
        return -1;
    }

    if (fread(buffer, 1, file_size, f) != file_size) {
        fclose(f);
        free(buffer);
        return -1;
    }
    fclose(f);

    // 4. Verify integrity
    ObjectID check;
    compute_hash(buffer, file_size, &check);

    if (memcmp(check.hash, id->hash, HASH_SIZE) != 0) {
        free(buffer);
        return -1;
    }

    // 5. Find header/data separator
    uint8_t *null_pos = memchr(buffer, '\0', file_size);
    if (!null_pos) {
        free(buffer);
        return -1;
    }

    // 6. Parse header
    char type_str[10];
    if (sscanf((char *)buffer, "%s %zu", type_str, len_out) != 2) {
        free(buffer);
        return -1;
    }

    size_t header_len = (size_t)(null_pos - buffer) + 1;
    if (header_len + *len_out > file_size) {
        free(buffer);
        return -1;
    }

    // 7. Map type
    if (strcmp(type_str, "blob") == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else {
        free(buffer);
        return -1;
    }

    // 8. Extract data
    *data_out = malloc(*len_out);
    if (!*data_out) {
        free(buffer);
        return -1;
    }

    memcpy(*data_out, null_pos + 1, *len_out);

    free(buffer);
    return 0;
}
