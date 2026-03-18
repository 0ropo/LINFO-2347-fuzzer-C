#include <stdio.h>
#include <sys/stat.h>

#include "fuzz.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: ./fuzzer path_to_extractor\n");
        return -1;
    }

    // printf("--- Starting fuzzing: injection on size,mode,uid ---\n");
    // fuzz_discover(argc, argv);

    printf("--- Starting typeflag tests ---\n");
    fuzz_typeflag(argc, argv);

    printf("--- Starting non-null termination tests ---\n");
    fuzz_non_null_termination(argc, argv);

    printf("--- Starting octal payload tests ---\n");
    fuzz_octal(argc, argv);

    printf("--- Starting string injection tests ---\n");
    fuzz_strings_injection(argc, argv);

    // printf("--- Starting tests on mtime ---\n");
    // fuzz_on_time(argc, argv);

    // printf("--- Starting tests on gnu_base256 ---\n");
    // fuzz_on_gnu_base256(argc, argv);

    printf("--- Starting tests on version ---\n");
    fuzz_version(argc, argv);

    printf("--- Starting tests on equal name and equal size ---\n");
    fuzz_equal_name_equal_size(argc, argv);

    fuzz_on_gnu_base256(argc, argv);


    printf("--- Starting tests on wiping ---\n");
    fuzz_by_truncation(argc, argv);
    return 0;
}
