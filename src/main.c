#include <stdio.h>
#include <sys/stat.h>

#include "fuzz.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: ./fuzzer path_to_extractor\n");
        return -1;
    }

    mkdir("successful_crashes", 0755);

    printf("--- Starting typeflag tests ---\n");
    fuzz_typeflag(argc, argv);

    printf("--- Starting fuzzing: injection on size,mode,uid ---\n");
    fuzz_discover(argc, argv);

    printf("--- Starting non-null termination tests ---\n");
    fuzz_non_null_termination(argc, argv);

    return 0;
}
