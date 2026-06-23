using System;
using System.Runtime.InteropServices;

namespace DonutCsharp
{
    // 1. DONUT CONSTANTS (Mapped from donut.h)
    public static class DonutConstants
    {
        // Errors
        public const int DONUT_ERROR_OK = 0;
        public const int DONUT_ERROR_SUCCESS = 0; // Alias for backward compatibility

        // Architectures
        public const int DONUT_ARCH_ANY = -1; // Only for VBS, JS and XSL
        public const int DONUT_ARCH_X86 = 1;
        public const int DONUT_ARCH_X64 = 2;
        public const int DONUT_ARCH_X84 = 3;  // x86 + amd64

        // Module Types
        public const int DONUT_MODULE_NET_DLL = 1;  // .NET DLL (Requires class and method)
        public const int DONUT_MODULE_NET_EXE = 2;  // .NET EXE (Executes Main if no class is given)
        public const int DONUT_MODULE_DLL = 3;      // Unmanaged DLL
        public const int DONUT_MODULE_EXE = 4;      // Unmanaged EXE
        public const int DONUT_MODULE_VBS = 5;      // VBScript
        public const int DONUT_MODULE_JS = 6;       // JavaScript or JScript

        // Instance Types
        public const int DONUT_INSTANCE_EMBED = 1;
        public const int DONUT_INSTANCE_HTTP = 2;
        public const int DONUT_INSTANCE_DNS = 3;  // Download from DNS server

        // Maximum Lengths and Sizes
        public const int DONUT_MAX_NAME = 256;
        public const int DONUT_MAX_DLL = 8;
        public const int DONUT_MAX_MODNAME = 8;
        public const int DONUT_SIG_LEN = 8;
        public const int DONUT_VER_LEN = 32;
        public const int DONUT_DOMAIN_LEN = 8;

        // Bypass AMSI/WLDP/ETW
        public const int DONUT_BYPASS_NONE = 1;
        public const int DONUT_BYPASS_ABORT = 2;
        public const int DONUT_BYPASS_CONTINUE = 3;

        // PE Headers Options
        public const int DONUT_HEADERS_OVERWRITE = 1;
        public const int DONUT_HEADERS_KEEP = 2;

        // Output Formats
        public const int DONUT_FORMAT_BINARY = 1;
        public const int DONUT_FORMAT_BASE64 = 2;
        public const int DONUT_FORMAT_C = 3;
        public const int DONUT_FORMAT_RUBY = 4;
        public const int DONUT_FORMAT_PYTHON = 5;
        public const int DONUT_FORMAT_POWERSHELL = 6;
        public const int DONUT_FORMAT_CSHARP = 7;
        public const int DONUT_FORMAT_HEX = 8;
        public const int DONUT_FORMAT_UUID = 9;

        // Compression
        public const int DONUT_COMPRESS_NONE = 1;
        public const int DONUT_COMPRESS_APLIB = 2;
        public const int DONUT_COMPRESS_LZNT1 = 3;
        public const int DONUT_COMPRESS_XPRESS = 4;

        // Entropy
        public const int DONUT_ENTROPY_NONE = 1;
        public const int DONUT_ENTROPY_RANDOM = 2;
        public const int DONUT_ENTROPY_DEFAULT = 3;

        // Exit Options
        public const int DONUT_OPT_EXIT_THREAD = 1;
        public const int DONUT_OPT_EXIT_PROCESS = 2;
        public const int DONUT_OPT_EXIT_BLOCK = 3;
    }

    // 2. DONUT_CONFIG STRUCTURE
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct DONUT_CONFIG
    {
        public uint len;
        public uint zlen;
        public int arch;
        public int bypass;
        public int headers;
        public int compress;
        public int entropy;
        public int format;
        public int exit_opt;
        public int thread;
        public uint oep;

        // Now we use our DONUT_MAX_NAME (256) constant in SizeConst
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DonutConstants.DONUT_MAX_NAME)] public string input;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DonutConstants.DONUT_MAX_NAME)] public string output;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DonutConstants.DONUT_MAX_NAME)] public string runtime;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DonutConstants.DONUT_MAX_NAME)] public string domain;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DonutConstants.DONUT_MAX_NAME)] public string cls;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DonutConstants.DONUT_MAX_NAME)] public string method;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DonutConstants.DONUT_MAX_NAME)] public string args;
        public int unicode;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 2056)] public string decoy;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DonutConstants.DONUT_MAX_NAME)] public string server;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DonutConstants.DONUT_MAX_NAME)] public string auth;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = DonutConstants.DONUT_MAX_NAME)] public string modname;

        public int mod_type;
        public int mod_len;
        public IntPtr mod;

        public int inst_type;
        public int inst_len;
        public IntPtr inst;

        public int pic_len;
        public IntPtr pic;
    }

    class Program
    {
        [DllImport("donut.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int DonutCreate(ref DONUT_CONFIG config);

        [DllImport("donut.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int DonutDelete(ref DONUT_CONFIG config);

        // Returns a pointer (IntPtr) to a string (const char*)
        [DllImport("donut.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr DonutError(int err);

        static void Main(string[] args)
        {
            // Check command line arguments
            if (args.Length < 1)
            {
                Console.WriteLine("Error: Required argument is missing.");
                Console.WriteLine("Usage: DonutCsharp.exe <input_executable> [output_payload]");
                Console.WriteLine(@"Example: DonutCsharp.exe C:\tools\mimikatz.exe custom_payload.bin");
                return;
            }

            DONUT_CONFIG config = new DONUT_CONFIG();

            // Setup input and output paths from CLI arguments
            config.input = args[0];
            config.output = args.Length >= 2 ? args[1] : "payload.bin";

            // Using constants makes the code 100% readable
            config.arch = DonutConstants.DONUT_ARCH_X84;
            config.bypass = DonutConstants.DONUT_BYPASS_CONTINUE;
            config.format = DonutConstants.DONUT_FORMAT_BINARY;
            config.inst_type = DonutConstants.DONUT_INSTANCE_EMBED;
            config.entropy = DonutConstants.DONUT_ENTROPY_DEFAULT;
            config.headers = DonutConstants.DONUT_HEADERS_OVERWRITE;
            config.exit_opt = DonutConstants.DONUT_OPT_EXIT_THREAD;
            config.compress = DonutConstants.DONUT_COMPRESS_NONE;

            Console.WriteLine("[*] Generating shellcode via Donut...");

            int err = DonutCreate(ref config);

            if (err == DonutConstants.DONUT_ERROR_SUCCESS)
            {
                Console.WriteLine($"[+] Shellcode successfully generated at: {config.output}");
                Console.WriteLine($"[+] Size: {config.pic_len} bytes");
            }
            else
            {
                // Get the error message pointer
                IntPtr errorPtr = DonutError(err);
                // Convert unmanaged pointer to a managed C# string
                string errorMessage = Marshal.PtrToStringAnsi(errorPtr);

                Console.WriteLine($"[-] Donut Error: {errorMessage}");
            }

            DonutDelete(ref config);
        }
    }
}