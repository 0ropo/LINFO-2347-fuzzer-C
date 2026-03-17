#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "help.h"

#define BLOCK_SIZE 512

void init_clean_archive(struct tar_t* archive) {
    memset(archive, 0, sizeof(struct tar_t));

    strcpy(archive->name, "test.txt");
    strcpy(archive->mode, "0000777");
    strcpy(archive->uid, "0000000");
    strcpy(archive->gid, "0000000");
    strcpy(archive->size, "00000000000");
    strcpy(archive->mtime, "00000000000");
    archive->typeflag = '0';
    strcpy(archive->magic, "ustar");
    memcpy(archive->version, "00", 2);
}

void write_zero_block(FILE *file) {
    char zeros[BLOCK_SIZE];
    memset(zeros, 0, sizeof(zeros));
    fwrite(zeros, 1, BLOCK_SIZE, file);
}

void generate_archive(struct tar_t* archive, const char* filename) {
    calculate_checksum(archive);

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        printf("Error generating archive: %s\n", filename);
        return;
    }

    fwrite(archive, sizeof(struct tar_t), 1, file);

    write_zero_block(file);
    write_zero_block(file);

    fclose(file);
    printf("Generated archive: %s\n", filename);
}

void test_attack(int argc, char* argv[], struct tar_t* archive, const char* success_name) {
    generate_archive(archive, "archive.tar");

    int result = validate_fuzzing(argc, argv);

    if (result == 1) {
        printf("[OK] Crash detected!\n");
        generate_archive(archive, success_name);
        printf("Saved crashing archive as: %s\n", success_name);
    } else if (result == 0) {
        printf("[KO] No crash.\n");
    } else {
        printf("[ERR] validate_fuzzing failed.\n");
    }
}

void brute_force_typeflag(int argc, char* argv[]) {
    for (int value = 0; value <= 255; value++) {
        struct tar_t archive;
        char success_name[128];

        init_clean_archive(&archive);
        archive.typeflag = (char)value;

        snprintf(success_name, sizeof(success_name), "successful_crashes/success_typeflag_%02X.tar", value);

        printf("\n--- Testing typeflag = 0x%02X", value);

        if (value >= 32 && value <= 126) {
            printf(" ('%c')", value);
        }

        test_attack(argc, argv, &archive, success_name);
    }
}

void fuzz_numbers(int argc, char* argv[]) {
    struct tar_t archive;
    const char* payload[] = {
            "-1",
            "0",
            "99999999999",
            "ABCDEFGHIJK",
            " ",
            "\xFF\xFF\xFF\xFF"
        };

    int payload_size = sizeof(payload);

    char success_name[50];
    for (int i = 0; i < payload_size; i++){
        init_clean_archive(&archive);
        strncpy(archive.size, payload[i],12);
        snprintf(success_name,50,"successful_crashes/success_size_injection_%d.tar",i);
        test_attack(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        strncpy(archive.mode, payload[i],8);
        snprintf(success_name,50,"successful_crashes/success_mode_injection_%d.tar",i);
        test_attack(argc, argv, &archive, success_name);


        init_clean_archive(&archive);
        strncpy(archive.uid, payload[i],8);
        snprintf(success_name,50,"successful_crashes/success_uid_injection_%d.tar",i);
        test_attack(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        strncpy(archive.gid, payload[i],8);
        snprintf(success_name,50,"successful_crashes/success_gid_injection_%d.tar",i);
        test_attack(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        strncpy(archive.mtime, payload[i],12);
        snprintf(success_name,50,"successful_crashes/success_mtime_injection_%d.tar",i);
        test_attack(argc, argv, &archive, success_name);

        init_clean_archive(&archive);
        strncpy(archive.version, payload[i],2);
        snprintf(success_name,50,"successful_crashes/success_version_injection_%d.tar",i);
        test_attack(argc, argv, &archive, success_name);
    }
}

void fuzz_text_injection(int argc, char* argv[]) {
    printf("--- Starting fuzzing: injection on text ---\n");

    struct tar_t archive;

    char success_name[50];

    const char* payload[] = {
        "/%x/%n/%s/%p"
        "%s%s%s%s%s%s%s",
        " ",
        "../../../../etc/passwd",
        "../",
        "A\x00B\x00C\x00D",
    };

    int payload_size = sizeof(payload);

    for (int i = 0; i < payload_size; i++) {
        init_clean_archive(&archive);
        strncpy(archive.name, payload[i],100);
        snprintf(success_name,50,"successful_crashes/success_name_injection_%d.tar",i);
        test_attack(argc, argv, &archive, success_name);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: ./fuzzer path_to_extractor\n");
        return -1;
    }

    mkdir("successful_crashes", 0755);

    printf("--- Starting fuzzing: brute force on typeflag ---\n");
    brute_force_typeflag(argc, argv);

    printf("--- Starting fuzzing: injection on size,mode,uid ---\n");
    fuzz_numbers(argc, argv);



    return 0;
}
