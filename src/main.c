#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "help.h"

/*
unsigned int calculate_checksum(struct tar_t* entry){
    memset(entry->chksum, ' ',8);
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
*/

// Fonctions of differents types of fuzzing

void init_clean_archive(struct tar_t* archive){
    memset(archive,0,sizeof(struct tar_t)); // cleanup of mémoire
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

void save_archive(struct tar_t* archive, const char* filename){
    calculate_checksum(archive);

    FILE *file = fopen(filename,"wb");

    if (file != NULL){
        fwrite(archive, sizeof(struct tar_t),1,file);
        fclose(file);
        printf("Created archive successfuly : %s\n", filename);
    }

    else{
        printf("Error creating the file : %s\n",filename);
    }
}

void test_attack(int argc, char* argv[], struct tar_t* archive, const char* name_succes){
    save_archive(archive, "archive.tar");

    int result = validate_fuzzing(argc, argv);

    if (result == 1){
        printf("[OK]Success ! Crash detected !\n");
        save_archive(archive,name_succes);
        printf("Archive saved under the name : %s\n",name_succes);
        printf("[KO]Failed !");
    }
}


int main(int argc, char* argv[]){
    if(argc < 2){
        printf("Usage: ./fuzzer path_to_file\n");
        return -1;
    }


    struct tar_t archive;

    printf("--- Starting generation of archive---\n\n");

    // Starting with a clean archive
    init_clean_archive(&archive);
    save_archive(&archive,"archive.tar");

    // First test buffer overflow
    printf("--- [1] Buffer Overflow testing with 100 ---\n\n");

    init_clean_archive(&archive);
    memset(archive.name,'A', 100);
    save_archive(&archive,"archive.tar");
    test_attack(argc,argv,&archive,"success_buffer_overflow.tar");


    return 0;
}
