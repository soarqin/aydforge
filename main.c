#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

void writeHeader(FILE *f) {
    unsigned char hdr[0x80] = {
        0x1A, 0x45, 0xDF, 0xA3, 0xA3, 0x42, 0x86, 0x81, 0x01, 0x42, 0xF7, 0x81, 0x01, 0x42, 0xF2, 0x81,
        0x04, 0x42, 0xF3, 0x81, 0x08, 0x42, 0x82, 0x88, 0x6D, 0x61, 0x74, 0x72, 0x6F, 0x73, 0x6B, 0x61,
        0x42, 0x87, 0x81, 0x04, 0x42, 0x85, 0x81, 0x02, 0x18, 0x53, 0x80, 0x67, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x05, 0x53, 0x39, 0x11, 0x4D, 0x9B, 0x74, 0xC1, 0xBF, 0x84, 0x0E, 0x47, 0xFF, 0xD8, 0x4D,
        0xBB, 0x8B, 0x53, 0xAB, 0x84, 0x15, 0x49, 0xA9, 0x66, 0x53, 0xAC, 0x81, 0xA1, 0x4D, 0xBB, 0x8B,
        0x53, 0xAB, 0x84, 0x16, 0x54, 0xAE, 0x6B, 0x53, 0xAC, 0x81, 0xF1, 0x4D, 0xBB, 0x8C, 0x53, 0xAB,
        0x84, 0x12, 0x54, 0xC3, 0x67, 0x53, 0xAC, 0x82, 0x01, 0xE8, 0x4D, 0xBB, 0x8D, 0x53, 0xAB, 0x84,
        0x1C, 0x53, 0xBB, 0x6B, 0x53, 0xAC, 0x83, 0x05, 0x52, 0xF7, 0xEC, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    fseek(f, 0, SEEK_SET);
    fwrite(&hdr, 1, sizeof(hdr), f);
}

void xorprocess(uint8_t *data, uint32_t size) {
    uint32_t i;
    for (i = 0; i < size; ++i) {
        data[i] = ((data[i] + i) ^ (0xD5u + 0x0Du * i)) - i;
    }
}

int decrypt(const char *filename, FILE *f) {
    uint16_t sz0, sz1;
    uint8_t data[0x80 + 0x100];
    uint32_t origsize;
    fseek(f, -4, SEEK_END);
    fread(&sz0, 2, 1, f);
    fread(&sz1, 2, 1, f);
    fseek(f, -(int)sz1, SEEK_END);
    origsize = ftell(f);
    fread(data, 1, sz1 - 4, f);
    xorprocess(data, sz1 - 4);
    fseek(f, 0, SEEK_SET);
    fwrite(data, 1, sz0, f);
    ftruncate(fileno(f), sz0 < 0x80 ? sz0 : origsize);
    fclose(f);
    {
        char *pathpos0 = strrchr(filename, '/'), *pathpos1 = strrchr(filename, '\\');
        char *pathpos = pathpos0 > pathpos1 ? pathpos0 : pathpos1;
        char pathprefix[256], realpath[256];
        if (pathpos) {
            memcpy(pathprefix, filename, pathpos - filename);
            pathprefix[pathpos - filename] = '/';
            pathprefix[pathpos - filename + 1] = 0;
        } else {
            pathprefix[0] = 0;
        }
        sprintf(realpath, "%s%s", pathprefix, (char*)data + sz0);
        if (rename(filename, realpath) == 0) {
            fprintf(stdout, "Decrypt: %s -> %s\n", filename, realpath);
            return 0;
        }
    }
    fprintf(stdout, "Decrypt: %s (FAILED)\n", filename);
    return 0;
}

int encrypt(const char *filename, FILE *f) {
    uint32_t osize, size, movesize;
    uint8_t data[0x80 + 0x100 + 4];
    char *pathpos0 = strrchr(filename, '/'), *pathpos1 = strrchr(filename, '\\');
    char *pathpos = pathpos0 > pathpos1 ? pathpos0 : pathpos1;
    const char *filepart = pathpos ? pathpos + 1 : filename;
    memset(data, 0, sizeof(data));
    fseek(f, 0, SEEK_SET);
    movesize = fread(data, 1, 0x80, f);
    strncpy((char*)&data[movesize], filepart, 256);
    if (movesize < 0x80) {
        ftruncate(fileno(f), 0x80);
    }
    fseek(f, 0, SEEK_END);
    osize = ftell(f);
    size = osize + movesize + strlen(filepart) + 1;
    *(uint16_t*)&data[size - osize] = movesize;
    *(uint16_t*)&data[size - osize + 2] = size + 4 - osize;
    xorprocess(data, size - osize);
    size += 4;
    fwrite(data, 1, size - osize, f);
    writeHeader(f);
    fclose(f);
    {
        struct stat sb;
        char mkvname[64];
        int i;
        char pathprefix[256];
        if (pathpos) {
            memcpy(pathprefix, filename, pathpos - filename);
            pathprefix[pathpos - filename] = '/';
            pathprefix[pathpos - filename + 1] = 0;
        } else {
            pathprefix[0] = 0;
        }
        for (i = 0; i < 99999999; ++i) {
            sprintf(mkvname, "%s%08d.mkv", pathprefix, i);
            if (stat(mkvname, &sb) != 0 && errno == ENOENT && rename(filename, mkvname) == 0) {
                fprintf(stdout, "Encrypt: %s -> %s\n", filename, mkvname);
                return 0;
            }
        }
    }
    fprintf(stdout, "Encrypt: %s (FAILED)\n", filename);
    return -1;
}

int main(int argc, char *argv[]) {
    FILE *f;
    char *ext;
    int i, succ = 0, fail = 0;
    if (argc < 2) {
        DIR *d = opendir(".");
        if (d) {
            struct dirent *dir;
            while ((dir = readdir(d)) != NULL) {
                const char *delim = strrchr(dir->d_name, '.');
                if (delim && stricmp(delim, ".mkv") == 0) {
                    f = fopen(dir->d_name, "r+b");
                    if (!f) {
                        fprintf(stdout, "Unable to open %s\n", dir->d_name);
                        ++fail;
                        continue;
                    }
                    if (decrypt(dir->d_name, f) == 0) {
                        ++succ;
                    } else {
                        ++fail;
                    }
                }
            }
        }
        if (succ + fail == 0) {
            fprintf(stderr, "Usage: aydforge <filename>...\n");
            return -1;
        }
        return -fail;
    }
    for (i = 1; i < argc; ++i) {
        int ret;
        f = fopen(argv[i], "r+b");
        if (!f) {
            fprintf(stdout, "Unable to open %s\n", argv[i]);
            ++fail;
            continue;
        }
        ext = strrchr(argv[i], '.');
        if (ext && stricmp(ext, ".mkv") == 0) {
            ret = decrypt(argv[i], f);
        } else {
            ret = encrypt(argv[i], f);
        }
        if (ret == 0) {
            ++succ;
        } else {
            ++fail;
        }
    }
    fprintf(stdout, "\n");
    if (succ) {
        fprintf(stdout, "Success: %d\n", succ);
    }
    if (fail) {
        fprintf(stdout, " Failed: %d\n", fail);
    }
    return -fail;
}

/* AliYunDrive file forge tool
 * File format:
 * 1. Simple MKV, with faked 0x80 bytes header
 * 2. Move first 0x80 bytes of original file to end of the new file
 * 3. Append original filename to end of the new file
 * 4. All 0x80+n bytes are encrypted by a simple encryption algorithm
 * 5. Append 2 bytes as size that moved from original file
 * 6. Append 2 bytes as total size appended(including 4 bytes in step 5 and 6)
 *
 * So the size of original file should be less than 2^32-0x80-strlen(filename)-1-4 bytes
 */
