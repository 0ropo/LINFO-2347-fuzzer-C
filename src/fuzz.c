#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include <stdlib.h>

#include "utils.h"
#include "fuzz.h"

/**
 * Run the extractor on generated archive and check if it crashes.
 * On crash, save the failing archive under success_<field>_<value>_<file>.
 */
void run_fuzz(int argc, char* argv[], struct tar_t* archive, const char* success_name) {
    generate_archive(archive, "archive.tar");

    int result = validate_fuzzing(argc, argv);

    if (result == 1) {
        printf("[OK] Crash detected!\n");
        generate_archive(archive, success_name);
        printf("Saved crashing archive as: %s\n", success_name);
    }
    else if (result == 0) {
        printf("[KO] No crash.\n");
    }
    else {
        printf("[ERR] validate_fuzzing failed.\n");
    }
}

/**
 * Fuzz typeflag header values [0..255].
 */
void fuzz_typeflag(int argc, char* argv[]) {
    const char* tested_file = get_filename(argv[1]);

    for (int value = 0; value <= 255; value++) {
        struct tar_t archive;
        char success_name[128];

        init_clean_archive(&archive);
        archive.typeflag = (char)value;

        snprintf(success_name, sizeof(success_name), "success_typeflag_%02X_%s.tar", value, tested_file);

        printf("\n--- Testing typeflag = 0x%02X", value);

        if (value >= 32 && value <= 126) {
            printf(" ('%c')", value);
        }

        run_fuzz(argc, argv, &archive, success_name);
    }
}

/**
 * Fuzz non-null termination of each header field by filling bytes with 'A'.
 */
void fuzz_non_null_termination(int argc, char* argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);

    field_desc fields[] = {
        {"name", offsetof(struct tar_t, name), sizeof(archive.name)},
        {"mode", offsetof(struct tar_t, mode), sizeof(archive.mode)},
        {"uid", offsetof(struct tar_t, uid), sizeof(archive.uid)},
        {"gid", offsetof(struct tar_t, gid), sizeof(archive.gid)},
        {"size", offsetof(struct tar_t, size), sizeof(archive.size)},
        {"mtime", offsetof(struct tar_t, mtime), sizeof(archive.mtime)},
        {"chksum", offsetof(struct tar_t, chksum), sizeof(archive.chksum)},
        {"linkname", offsetof(struct tar_t, linkname), sizeof(archive.linkname)},
        {"magic", offsetof(struct tar_t, magic), sizeof(archive.magic)},
        {"version", offsetof(struct tar_t, version), sizeof(archive.version)},
        {"uname", offsetof(struct tar_t, uname), sizeof(archive.uname)},
        {"gname", offsetof(struct tar_t, gname), sizeof(archive.gname)}
    };

    int n = sizeof(fields) / sizeof(fields[0]);

    for (int i = 0; i < n; i++) {
        char *field_ptr;
        char success_name[128];

        init_clean_archive(&archive);

        field_ptr = ((char *)&archive) + fields[i].offset;

        memset(field_ptr, 'A', fields[i].size);

        snprintf(success_name, sizeof(success_name), "success_non_null_termination_%s_%s.tar", fields[i].name, tested_file);

        printf("\n--- Testing non-null termination on %s ---\n", fields[i].name);

        run_fuzz(argc, argv, &archive, success_name);
    }
}

/**
 * Fuzz header fields with octal-like payloads to test parser handling.
 */
void fuzz_octal(int argc, char *argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);

    field_desc fields[] = {
        {"name", offsetof(struct tar_t, name), sizeof(archive.name)},
        {"mode", offsetof(struct tar_t, mode), sizeof(archive.mode)},
        {"uid", offsetof(struct tar_t, uid), sizeof(archive.uid)},
        {"gid", offsetof(struct tar_t, gid), sizeof(archive.gid)},
        {"size", offsetof(struct tar_t, size), sizeof(archive.size)},
        {"mtime", offsetof(struct tar_t, mtime), sizeof(archive.mtime)},
        {"chksum", offsetof(struct tar_t, chksum), sizeof(archive.chksum)},
        {"linkname", offsetof(struct tar_t, linkname), sizeof(archive.linkname)},
        {"magic", offsetof(struct tar_t, magic), sizeof(archive.magic)},
        {"version", offsetof(struct tar_t, version), sizeof(archive.version)},
        {"uname", offsetof(struct tar_t, uname), sizeof(archive.uname)},
        {"gname", offsetof(struct tar_t, gname), sizeof(archive.gname)}
    };

    const char* payload[] = {"88888888","99999999999"," 123","123 ","+123","-000001","0x123","\000123","0000000", "-200","-2147483648","2147483647","9223372036854775807"};

    int fields_size = sizeof(fields) / sizeof(fields[0]);
    int payload_size = sizeof(payload)/sizeof(payload[0]);

    for (int i = 0; i < fields_size; i++) {
        char *field_ptr;
        char success_name[128];
        for (int j = 0; j < payload_size; j++) {
            init_clean_archive(&archive);
            field_ptr = (char *)((char *)&archive + fields[i].offset);
            strncpy(field_ptr, payload[j], fields[i].size);
            snprintf(success_name,sizeof(success_name),"success_%s_octal_%d_%s.tar", fields[i].name, j, tested_file);
            run_fuzz(argc, argv, &archive, success_name);
        }
    }
}

/**
 * Fuzz multiple string payloads into every field in tar header.
 */
void fuzz_strings_injection(int argc, char* argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);

   field_desc fields[] = {
        {"name", offsetof(struct tar_t, name), sizeof(archive.name)},
        {"mode", offsetof(struct tar_t, mode), sizeof(archive.mode)},
        {"uid", offsetof(struct tar_t, uid), sizeof(archive.uid)},
        {"gid", offsetof(struct tar_t, gid), sizeof(archive.gid)},
        {"size", offsetof(struct tar_t, size), sizeof(archive.size)},
        {"mtime", offsetof(struct tar_t, mtime), sizeof(archive.mtime)},
        {"chksum", offsetof(struct tar_t, chksum), sizeof(archive.chksum)},
        {"linkname", offsetof(struct tar_t, linkname), sizeof(archive.linkname)},
        {"magic", offsetof(struct tar_t, magic), sizeof(archive.magic)},
        {"version", offsetof(struct tar_t, version), sizeof(archive.version)},
        {"uname", offsetof(struct tar_t, uname), sizeof(archive.uname)},
        {"gname", offsetof(struct tar_t, gname), sizeof(archive.gname)}
    };

    const char* payload[] = {"../../../../../../etc/hostname", "/%x/%n/%s/%p","%s%s%s%s%s%s%s","\n\n\n\n\n\n\n\n","A\x00B\x00C\x00D"};

    int fields_size = sizeof(fields) / sizeof(fields[0]);
    int payload_size = sizeof(payload) / sizeof(payload[0]);

    for (int i = 0; i < fields_size; i++) {
        for (int j = 0; j < payload_size; j++) {
            char success_name[128];
            init_clean_archive(&archive);

            if (strcmp(fields[i].name,"linkname") == 0){
                archive.typeflag = '2';
            }

            char *field_ptr = (char*)((char*)&archive + fields[i].offset);
            strncpy(field_ptr, payload[j],fields[i].size);
            snprintf(success_name, sizeof(success_name), "success_%s_string_injection_%d_%s.tar", fields[i].name, j, tested_file);
            run_fuzz(argc, argv, &archive, success_name);
        }
    }
}

/**
 * Fuzz GNU base-256 numeric encoding in selected header fields.
 */
void fuzz_on_gnu_base256(int argc, char* argv[]){
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);

    field_desc fields[] = {
        {"size", offsetof(struct tar_t, size), sizeof(archive.size)},
        {"uid", offsetof(struct tar_t, uid), sizeof(archive.uid)},
        {"gid", offsetof(struct tar_t, gid), sizeof(archive.gid)},
        {"mtime", offsetof(struct tar_t, mtime), sizeof(archive.mtime)},
    };

    const char payload_big[] = {'\x80', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF'};
    const char payload_negative[] = {'\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF'};
    int fields_size = sizeof(fields) / sizeof(fields[0]);

    for(int i = 0; i < fields_size; i++){
        char success_name[128];
        char *field_ptr;

        init_clean_archive(&archive);
        field_ptr = (char *)((char *)&archive + fields[i].offset);
        memcpy(field_ptr, payload_big, fields[i].size);
        snprintf(success_name, sizeof(success_name), "success_%s_base256_huge_%s.tar", fields[i].name, tested_file);
        run_fuzz(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        field_ptr = (char *)((char *)&archive + fields[i].offset);
        memcpy(field_ptr, payload_negative, fields[i].size);
        snprintf(success_name, sizeof(success_name), "success_%s_base256_negative_%s.tar", fields[i].name, tested_file);
        run_fuzz(argc, argv, &archive, success_name);
    }
}

/**
 * Fuzz version header field [00..99].
 */
void fuzz_version(int argc, char* argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);
    char success_name[128];

    for (char c1 = '0'; c1 <= '9'; c1++) {
        for (char c2 = '0'; c2 <= '9'; c2++) {
            init_clean_archive(&archive);

            archive.version[0] = c1;
            archive.version[1] = c2;

            snprintf(success_name, sizeof(success_name), "success_version_%c%c_%s.tar", c1, c2, tested_file);

            printf("\n--- Testing version=\"%c%c\" ---\n", c1, c2);

            run_fuzz(argc, argv, &archive, success_name);
        }
    }
}

/**
 * Set the tar size field to an octal representation of a regular file size.
 * @param archive: tar header which size will be set.
 * @param size: numeric file size.
 */
static void set_file_size(struct tar_t *archive, unsigned long long size) {
    memset(archive->size, 0, sizeof(archive->size));
    snprintf(archive->size, sizeof(archive->size), "%011llo", size);
    archive->typeflag = '0';
}

/**
 * Write a tar header with optional file data to a file.
 * @param file: open file pointer in write mode.
 * @param entry: tar header to write.
 * @param data: optional file data to write after header.
 * @param size: size of file data.
 */
static void write_header_with_data(FILE *file, struct tar_t *entry, const unsigned char *data, size_t size) {
    calculate_checksum(entry);
    fwrite(entry, sizeof(struct tar_t), 1, file);

    if (size > 0 && data != NULL) {
        char block[BLOCK_SIZE];
        memset(block, 0, sizeof(block));
        memcpy(block, data, size);
        fwrite(block, 1, BLOCK_SIZE, file);
    }
}

/**
 * Fuzz tar headers with duplicate names and sizes.
 */
void fuzz_duplicate_headers(int argc, char* argv[]) {
    struct tar_t first;
    struct tar_t second;
    const char* tested_file = get_filename(argv[1]);
    char success_name[128];
    unsigned long long size = 1;

    unsigned char data1[1] = {'A'};
    unsigned char data2[1] = {'B'};

    init_clean_archive(&first);
    init_clean_archive(&second);

    strcpy(first.name, "test.txt");
    strcpy(second.name, "test.txt");

    set_file_size(&first, size);
    set_file_size(&second, size);

    snprintf(success_name, sizeof(success_name),
             "success_equal_name_equal_size_%s.tar",
             tested_file);

    printf("\n--- Testing same-name same-size update ---\n");

    FILE *file = fopen("archive.tar", "wb");
    if (file == NULL) {
        printf("[ERR] Error generating archive.tar\n");
        return;
    }

    write_header_with_data(file, &first, data1, size);
    write_header_with_data(file, &second, data2, size);

    write_zero_block(file);
    write_zero_block(file);
    fclose(file);

    int result = validate_fuzzing(argc, argv);

    if (result == 1) {
        printf("[OK] Crash detected!\n");

        file = fopen(success_name, "wb");
        if (file == NULL) {
            printf("[ERR] Error generating %s\n", success_name);
            return;
        }

        write_header_with_data(file, &first, data1, size);
        write_header_with_data(file, &second, data2, size);

        write_zero_block(file);
        write_zero_block(file);
        fclose(file);

        printf("Saved crashing archive as: %s\n", success_name);
    }
    else if (result == 0) {
        printf("[KO] No crash.\n");
    }
    else {
        printf("[ERR] validate_fuzzing failed.\n");
    }
}

/**
 * Fuzz by truncating the archive at various positions in header fields.
 */
void fuzz_by_truncation(int argc, char* argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);

   field_desc fields[] = {
        {"name", offsetof(struct tar_t, name), sizeof(archive.name)},
        {"mode", offsetof(struct tar_t, mode), sizeof(archive.mode)},
        {"uid", offsetof(struct tar_t, uid), sizeof(archive.uid)},
        {"gid", offsetof(struct tar_t, gid), sizeof(archive.gid)},
        {"size", offsetof(struct tar_t, size), sizeof(archive.size)},
        {"mtime", offsetof(struct tar_t, mtime), sizeof(archive.mtime)},
        {"chksum", offsetof(struct tar_t, chksum), sizeof(archive.chksum)},
        {"linkname", offsetof(struct tar_t, linkname), sizeof(archive.linkname)},
        {"magic", offsetof(struct tar_t, magic), sizeof(archive.magic)},
        {"version", offsetof(struct tar_t, version), sizeof(archive.version)},
        {"uname", offsetof(struct tar_t, uname), sizeof(archive.uname)},
        {"gname", offsetof(struct tar_t, gname), sizeof(archive.gname)}
    };

    int fields_size = sizeof(fields) / sizeof(fields[0]);

    for(int i = 0; i < fields_size;i++){
        char success_name[256];
        FILE *f;
        int result;

        init_clean_archive(&archive);

        strncpy(archive.magic, "ustar", 6);
        memcpy(archive.version, "00", 2);

        size_t cut_position = fields[i].offset + fields[i].size;

        f = fopen("archive.tar", "wb");
        if (f){
            fwrite(&archive, 1, cut_position, f);
            fclose(f);
        }

        result = validate_fuzzing(argc,argv);

        if (result == 1){
            snprintf(success_name, sizeof(success_name), "success_%s_truncation_%s.tar", fields[i].name, tested_file);
            f = fopen(success_name, "wb");
            if (f){
                fwrite(&archive, 1, cut_position, f);
                fclose(f);
            }
        }
    }
}

/**
 * Fuzz by truncating the archive in the middle of file data.
 */
void fuzz_by_truncation_on_data(int argc, char* argv[]){
    struct tar_t archive;
    const char* tested_file = argv[1];
    char success_name[256];
    FILE *f;
    int result;

    init_clean_archive(&archive);

    strncpy(archive.name,"bait.txt",11);
    archive.typeflag = '0';

    memcpy(archive.magic, "ustar", sizeof(archive.magic));
    memcpy(archive.version, "00", sizeof(archive.version));

    strncpy(archive.size, "00000002000", sizeof(archive.size));
    f = fopen("archive.tar", "wb");
    if (f){
        fwrite(&archive, 1, 512, f);
        fclose(f);
    }

    result = validate_fuzzing(argc, argv);
    if (result == 1){
        snprintf(success_name, sizeof(success_name), "success_truncation_on_data_%s_%s.tar",archive.name, tested_file);
        f = fopen(success_name, "wb");
        if (f){
            fwrite(&archive, 1, 512, f);
            fclose(f);
        }
    }

}

/**
 * Fuzz by forging the checksum field.
 */
void fuzz_by_checksum_forgery(int argc, char* argv[]) {
    struct tar_t archive;
    const char* tested_file = get_filename(argv[1]);
    char success_name[256];
    FILE *f;
    int result;

    memset(&archive, '\xFF', sizeof(struct tar_t));
    memcpy(archive.magic, "ustar", sizeof(archive.magic));
    memcpy(archive.version, "00", sizeof(archive.version));
    strncpy(archive.name, "false.txt", sizeof(archive.name));
    archive.typeflag = '0';

    memset(archive.chksum, ' ',8);

    int signed_sum = 0;
    unsigned int unsigned_sum = 0;
    char *ptr = (char *)&archive;

    for(int i = 0; i < 512;i++){
        signed_sum += ptr[i];
        unsigned_sum += (unsigned char)ptr[i];
    }

    snprintf(archive.chksum, 8, "%06o", unsigned_sum + 1);

    f = fopen("archive.tar", "wb");
    fwrite(&archive,1,512,f);
    fclose(f);

    result = validate_fuzzing(argc, argv);
    if (result == 1){
        snprintf(success_name, sizeof(success_name), "success_checksum1_forgery_%s_%s.tar",  archive.name, tested_file);
        f = fopen(success_name, "wb");
        if (f){
            fwrite(&archive, 1, 512, f);
            fclose(f);
        }
    }

    snprintf(archive.chksum, 8, "%06o", signed_sum & 0x3FFFF);
    f = fopen("archive.tar", "wb");
    fwrite(&archive, 1, 512, f);
    fclose(f);

    result = validate_fuzzing(argc,argv);
    if (result == 1){
        snprintf(success_name, sizeof(success_name), "success_checksum2_forgery_%s_%s.tar",  archive.name, tested_file);
        f = fopen(success_name, "wb");
        if (f){
            fwrite(&archive, 1, 512, f);
            fclose(f);
        }
    }
}