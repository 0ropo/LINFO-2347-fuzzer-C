#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct tar_t
{                              /* byte offset */
    char name[100];               /*   0 */
    char mode[8];                 /* 100 */
    char uid[8];                  /* 108 */
    char gid[8];                  /* 116 */
    char size[12];                /* 124 */
    char mtime[12];               /* 136 */
    char chksum[8];               /* 148 */
    char typeflag;                /* 156 */
    char linkname[100];           /* 157 */
    char magic[6];                /* 257 */
    char version[2];              /* 263 */
    char uname[32];               /* 265 */
    char gname[32];               /* 297 */
    char devmajor[8];             /* 329 */
    char devminor[8];             /* 337 */
    char prefix[155];             /* 345 */
    char padding[12];             /* 500 */
};


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


int main(int argc, char* argv[])
{
    struct tar_t archive;
    memset(&archive,0,sizeof(struct tar_t)); // cleanup de la mémoire
    strcpy(archive.name, "test.txt");
    strcpy(archive.mode, "0000777");
    strcpy(archive.uid, "0000000");
    strcpy(archive.gid, "0000000");
    strcpy(archive.size, "00000000000");
    strcpy(archive.mtime, "00000000000");
    archive.typeflag = '0';
    strcpy(archive.magic, "ustar");
    memcpy(archive.version, "00", 2);
    calculate_checksum(&archive);
    FILE *file = fopen("test.tar","wb");

    if (file != NULL){
        fwrite(&archive, sizeof(struct tar_t),1,file);
        fclose(file);
        printf("Created archive successfuly");
    }

    else{
        printf("Error creating the file");
        return -1;
    }
    return 0;
}
