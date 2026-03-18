#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

/**
 * Computes the checksum for a tar header and encode it on the header
 * @param entry: The tar header
 * @return the value of the checksum
 */
unsigned int calculate_checksum(struct tar_t* entry){
    // use spaces for the checksum bytes while calculating the checksum
    memset(entry->chksum, ' ', 8);

    // sum of entire metadata
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++){
        check += raw[i];
    }

    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);

    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}

/**
 * Launches another executable given as argument,
 * parses its output and check whether or not it matches "*** The program has crashed ***".
 * @param the path to the executable
 * @return -1 if the executable cannot be launched,
 *          0 if it is launched but does not print "*** The program has crashed ***",
 *          1 if it is launched and prints "*** The program has crashed ***".
 *
 * BONUS (for fun, no additional marks) without modifying this code,
 * compile it and use the executable to restart our computer.
 */
int validate_fuzzing(int argc, char* argv[])
{
    if (argc < 2)
        return -1;
    int rv = 0;
    char cmd[51];
    strncpy(cmd, argv[1], 25);
    cmd[26] = '\0';
    strncat(cmd, " archive.tar", 25);
    char buf[33];
    FILE *fp;

    if ((fp = popen(cmd, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    if(fgets(buf, 33, fp) == NULL) {
        printf("No output\n");
        goto finally;
    }
    if(strncmp(buf, "*** The program has crashed ***\n", 33)) {
        printf("Not the crash message\n");
        goto finally;
    } else {
        printf("Crash message\n");
        rv = 1;
        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }
    return rv;
}

/**
 * Initialize a tar header with default internal values.
 * Used by fuzzing tests to start from a reproducible clean header.
 * @param archive: pointer to tar_t structure to initialize a tar header.
 */
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

/**
 * Write a single 512-byte zero block to a file.
 * Tar format requires two zero blocks at end of archive.
 * @param file: open file pointer in write mode.
 */
void write_zero_block(FILE *file) {
    char zeros[BLOCK_SIZE];
    memset(zeros, 0, sizeof(zeros));
    fwrite(zeros, 1, BLOCK_SIZE, file);
}

/**
 * Write a complete single-entry tar archive to disk from the tar header.
 * This writes the header, plus two zero blocks to terminate the archive.
 * @param archive: tar header to write.
 * @param filename: output archive file name.
 */
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
}

/**
 * Write one data block for a tar file entry, padded to 512-byte boundary.
 * @param file: open output file pointer.
 * @param data: data bytes to write.
 * @param size: data length in bytes.
 */
static void write_padded_data(FILE *file, const unsigned char *data, size_t size) {
    char block[BLOCK_SIZE];
    size_t written = 0;

    while (written < size) {
        size_t chunk = size - written;
        if (chunk > BLOCK_SIZE) {
            chunk = BLOCK_SIZE;
        }

        memset(block, 0, BLOCK_SIZE);
        memcpy(block, data + written, chunk);
        fwrite(block, 1, BLOCK_SIZE, file);

        written += chunk;
    }

    if (size == 0) {
        return;
    }
}

/**
 * Extract the filename component from a path (last / or \\ separator).
 * @param path: path string to parse.
 * @return pointer to the filename substring (inside path string).
 */
const char* get_filename(const char* path) {
    const char* last_slash = strrchr(path, '/');
    const char* last_backslash = strrchr(path, '\\');
    const char* last_sep = last_slash;

    if (last_backslash && (!last_sep || last_backslash > last_sep)) {
        last_sep = last_backslash;
    }

    return last_sep ? last_sep + 1 : path;
}

/**
 * Generate a tar archive containing two entries with same filename and size.
 * This helper is used for specific fuzzing edge cases where duplicates are needed.
 * @param first: metadata for first entry.
 * @param data1: payload bytes for first entry.
 * @param data1_size: size of first payload.
 * @param second: metadata for second entry.
 * @param data2: payload bytes for second entry.
 * @param data2_size: size of second payload.
 * @param filename: output tar archive file.
 */
void generate_two_entry_archive_same_name_same_size(
    struct tar_t* first,
    const unsigned char* data1,
    size_t data1_size,
    struct tar_t* second,
    const unsigned char* data2,
    size_t data2_size,
    const char* filename
) {
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        printf("Error generating archive: %s\n", filename);
        return;
    }

    calculate_checksum(first);
    fwrite(first, sizeof(struct tar_t), 1, file);
    write_padded_data(file, data1, data1_size);

    calculate_checksum(second);
    fwrite(second, sizeof(struct tar_t), 1, file);
    write_padded_data(file, data2, data2_size);

    write_zero_block(file);
    write_zero_block(file);

    fclose(file);
}
