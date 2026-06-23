![Alt text](https://github.com/Zuigetzu/Donut-CustomHost/blob/master/img/donut_logo_white.jpg?raw=true "Donut Logo")

<p>Current version: <a href="https://github.com/Zuigetzu/Donut-CustomHost/releases">v1.2</a></p>

<h2>Table of contents</h2>

<ol>
  <li><a href="#how">Key Differences</a></li>
  <li><a href="#usage">Usage</a></li>
  <li><a href="#library-usage">Using Donut as a Library (Fixed & Ready-to-Use Examples)</a></li>
  <li><a href="#disclaimer">Disclaimer</a></li>
  <li><a href="#credits">Acknowledgments / Credits</a></li>
</ol>

<h2 id="how">1. Key Differences</h2>

<h3>Advanced OPSEC Features (Fork Exclusives)</h3>

<p>To maximize stealth and evade modern EDRs, this specific fork implements several advanced techniques not found in the original branch:</p>

<ul>
  <li><strong>Custom CLR Host:</strong> By providing custom in-memory implementations of <code>IHostAssemblyManager</code>, <code>IHostAssemblyStore</code>, and <code>IHostMemoryManager</code>, Donut successfully intercepts the assembly loading process (<code>AppDomain.Load_2</code>). Instead of relying on the default Fusion loader (which leaves tracking artifacts and may drop files to disk), our custom Assembly Store provides the payload directly from memory as an <code>IStream</code> matching the exact Fully Qualified Name (FQN).</li>
  <li><strong>Memory Tracking Evasion:</strong> The custom Memory Manager acts as a mirage, returning <code>S_OK</code> to blind EDR heuristics looking for malicious memory tracking events.</li>
  <li><strong>Architecture-Aware ETW Bypass:</strong> We have implemented an advanced Tail Jump technique. Instead of blindly patching <code>NtTraceEvent</code> with a standard <code>RET</code> instruction—which can corrupt the stack on x86/WoW64 environments (where <code>stdcall</code> actually requires <code>RET 10h</code>)—the loader dynamically scans the function for its legitimate return instruction. It then patches the entry point with a relative <code>JMP</code> (<code>0xE9</code>) pointing directly to that native return. This ensures perfect stack alignment and stability across both x64 and x86 architectures, silently dropping all ETW events without triggering process crashes.</li>
  <li><strong>AMSI/WLDP Patching Removal:</strong> Traditional AMSI patching requires modifying memory protections (<code>VirtualProtect</code>) on native DLLs, an action highly monitored by modern EDRs. Since our Custom CLR Host inherently evades the telemetry that triggers these scans, we deliberately removed the default AMSI patches to maintain a pristine, untampered memory footprint.</li>
  <li><strong>Shellcode Size Optimization (Padding Bug Fix):</strong> The original generator had a memory allocation flaw in <code>donut.c</code>. It calculated the payload size by adding <code>sizeof(DONUT_INSTANCE)</code> to <code>c-&gt;mod_len</code>. Because <code>DONUT_INSTANCE</code> contains a <code>DONUT_MODULE</code> union, the module structure (~1.3 KB) was allocated twice, leaving dead memory (null bytes) at the end of the final <code>.bin</code>. We fixed this by dynamically calculating the base size with <code>offsetof(DONUT_INSTANCE, module)</code>, resulting in a 100% space-efficient payload with zero bloat.</li>
</ul>

<h2 id="usage">2. Usage</h2>

<p>The following table lists switches supported by the command line version of the generator.</p>

<table border="1">
  <tr>
    <th>Switch</th>
    <th>Argument</th>
    <th>Description</th>
  </tr>
  
  <tr>
    <td><strong>-a</strong></td>
    <td><var>arch</var></td>
    <td>Target architecture for loader : 1=x86, 2=amd64, 3=x86+amd64(default).</td>
  </tr>
  
  <tr>
    <td><strong>-b</strong></td>
    <td><var>level</var></td>
    <td>Behavior for bypassing AMSI/WLDP : 1=None, 2=Abort on fail, 3=Continue on fail.(default)</td>
  </tr>

  <tr>
    <td><strong>-k</strong></td>
    <td><var>headers</var></td>
    <td>Preserve PE headers. 1=Overwrite (default), 2=Keep all</td>
  </tr>

  <tr>
    <td><strong>-j</strong></td>
    <td><var>decoy</var></td>
    <td>Optional path of decoy module for Module Overloading.</td>
  </tr>
  
  <tr>
    <td><strong>-c</strong></td>
    <td><var>class</var></td>
    <td>Optional class name. (required for .NET DLL) Can also include namespace: e.g <em>namespace.class</em></td>
  </tr>  
  
  <tr>
    <td><strong>-d</strong></td>
    <td><var>name</var></td>
    <td>AppDomain name to create for .NET. If entropy is enabled, one will be generated randomly.</td>
  </tr>  

  <tr>
    <td><strong>-e</strong></td>
    <td><var>level</var></td>
    <td>Entropy level. 1=None, 2=Generate random names, 3=Generate random names + use symmetric encryption (default)</td>
  </tr>
  
  <tr>
    <td><strong>-f</strong></td>
    <td><var>format</var></td>
    <td>The output format of loader saved to file. 1=Binary (default), 2=Base64, 3=C, 4=Ruby, 5=Python, 6=PowerShell, 7=C#, 8=Hexadecimal</td>
  </tr>
  
  <tr>
    <td><strong>-m</strong></td>
    <td><var>name</var></td>
    <td>Optional method or function for DLL. (a method is required for .NET DLL)</td>
  </tr>
  
  <tr>
    <td><strong>-n</strong></td>
    <td><var>name</var></td>
    <td>Module name for HTTP staging. If entropy is enabled, one is generated randomly.</td>
  </tr>
  
  <tr>
    <td><strong>-o</strong></td>
    <td><var>path</var></td>
    <td>Specifies where Donut should save the loader. Default is "loader.bin" in the current directory.</td>
  </tr>

  <tr>
    <td><strong>-p</strong></td>
    <td><var>parameters</var></td>
    <td>Optional parameters/command line inside quotations for DLL method/function or EXE.</td>
  </tr>
  
  <tr>
    <td><strong>-r</strong></td>
    <td><var>version</var></td>
    <td>CLR runtime version. MetaHeader used by default or v4.0.30319 if none available.</td>
  </tr>
  
  <tr>
    <td><strong>-s</strong></td>
    <td><var>server</var></td>
    <td>URL for the HTTP server that will host a Donut module. Credentials may be provided in the following format: <pre>https://username:password@192.168.0.1/</pre></td>
  </tr>

  <tr>
    <td><strong>-t</strong></td>
    <td></td>
    <td>Run the entrypoint of an unmanaged/native EXE as a thread and wait for thread to end.</td>
  </tr>
  
  <tr>
    <td><strong>-w</strong></td>
    <td></td>
    <td>Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)</td>
  </tr>
  
  <tr>
    <td><strong>-x</strong></td>
    <td><var>option</var></td>
    <td>Determines how the loader should exit. 1=exit thread (default), 2=exit process, 3=Do not exit or cleanup and block indefinitely</td>
  </tr>

  <tr>
    <td><strong>-y</strong></td>
    <td><var>addr</var></td>
    <td>Creates a new thread for the loader and continues execution at an address that is an offset relative to the host process's executable. The value provided is the offset. This option supports loaders that wish to resume execution of the host process after donut completes execution.</td>
  </tr>

  <tr>
    <td><strong>-z</strong></td>
    <td><var>engine</var></td>
    <td>Pack/Compress the input file. 1=None, 2=aPLib, 3=LZNT1, 4=Xpress, 5=Xpress Huffman. Currently, the last three are only supported on Windows.</td>
  </tr>
</table>

<h3 id="requirements">Payload Requirements</h2>

<p>There are some specific requirements that your payload must meet in order for Donut to successfully load it.</p>

<h3 id="requirements-dotnet">.NET Assemblies</h2>

<ul>
  <li>The entry point method must only take strings as arguments, or take no arguments.</li>
  <li>The entry point method must be marked as public and static.</li>
  <li>The class containing the entry point method must be marked as public.</li>
  <li>The Assembly must NOT be a Mixed Assembly (contain both managed and native code).</li>
  <li>As such, the Assembly must NOT contain any Unmanaged Exports.</li>
</ul>

<h3 id="requirements-native">Native EXE/DLL</h2>

<ul>
  <li>Binaries built with Cygwin are unsupported.</li>
</ul>

<p>Cygwin executables use initialization routines that expect the host process to be running from disk. If executing from memory, the host process will likely crash.</p>

<h3 id="requirements-dotnet">Unmanaged DLLs</h2>

<ul>
  <li>A user-specified entry point method must only take a string as an argument, or take no arguments. We have provided an <a href="https://github.com/Zuigetzu/Donut-CustomHost/blob/master/DonutTest/dlltest.c/">example</a>.</li>
</ul>

<h3 id="library-usage">3. Using Donut as a Library (Fixed & Ready-to-Use Examples)</h3>

<p>In the original repository, using Donut as a library (<code>donut.lib</code> / <code>donut.dll</code> / <code>donut.a</code>) often resulted in compilation and linking errors. <strong>This fork explicitly fixes those issues</strong>, allowing seamless integration into your custom droppers and C2 tooling.</p>

<p>We have provided ready-to-compile examples inside the <code>lib/</code> directory of this repository for C, Go, and C#.</p>

<h4>1. C/C++ Example (<code>lib/main.c</code>)</h4>

<p>Inside the <code>lib</code> folder, you will find <code>main.c</code> and a dedicated <code>Makefile</code>. To build the example tool using the static/dynamic library, simply navigate to <code>lib/</code> and run <code>nmake</code> (or <code>make</code>):</p>

```c
// Snippet from lib/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "donut.h"

int main(int argc, char *argv[]) {
    DONUT_CONFIG config;
    int err;

    // ... [Initialization] ...
    
    // Configure parameters
    config.inst_type = DONUT_INSTANCE_EMBED;
    config.arch      = DONUT_ARCH_X84;
    config.bypass    = DONUT_BYPASS_CONTINUE;
    config.headers   = DONUT_HEADERS_OVERWRITE;
    config.format    = DONUT_FORMAT_BINARY;
    config.compress  = DONUT_COMPRESS_NONE;
    config.entropy   = DONUT_ENTROPY_DEFAULT;
    config.exit_opt  = DONUT_OPT_EXIT_THREAD;
    config.unicode   = 0;

    err = DonutCreate(&config);

    if (err == DONUT_ERROR_OK) {
        printf("[+] Shellcode successfully generated at: %s\n", config.output);
    } else {
        printf("[-] Error generating shellcode: %s\n", DonutError(err));
    }

    DonutDelete(&config);
    return 0;
}
```

<h4>2. Golang Example (<code>lib/main.go</code>)</h4>

<p>Go can natively interop with Donut through CGO. The <code>main.go</code> file inside <code>lib/</code> is fully configured with the appropriate <code>CFLAGS</code> and <code>LDFLAGS</code> to link against the fixed library.</p>

```Go
// Snippet from lib/main.go
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
    // ... [Initialization & String conversions] ...

	config.arch = C.DONUT_ARCH_X84
	config.bypass = C.DONUT_BYPASS_CONTINUE
	config.format = C.DONUT_FORMAT_BINARY
	// ... [Other Configs] ...

	err := C.DonutCreate(&config)

	if err == C.DONUT_ERROR_OK {
		outName := C.GoString((*C.char)(unsafe.Pointer(&config.output[0])))
		fmt.Printf("[+] Shellcode successfully generated at: %s\n", outName)
	} else {
		errMsg := C.GoString(C.DonutError(err))
		fmt.Printf("[-] Donut Error. Code: %d - %s\n", err, errMsg)
	}

	C.DonutDelete(&config)
}
```

<h4>3. C# Example via P/Invoke (<code>lib/DonutCsharp/</code>)</h4>

<p>When compiling a C# tool that interacts with <code>donut.dll</code> via P/Invoke, a common issue is having to distribute the unmanaged DLL alongside your <code>.exe</code>.</p>

<p>Inside <code>lib/DonutCsharp/</code> you will find a complete Visual Studio Solution already configured with the <strong>Costura.Fody</strong> NuGet package. Costura automatically embeds the unmanaged <code>donut.dll</code> (for both x86 and x64) statically inside your managed assembly. <strong>You just need to open the <code>.sln</code> and compile.</strong> The output will be a single, standalone executable ready for your operations.</p>

```C#
// Snippet from lib/DonutCsharp/Program.cs
using System;
using System.Runtime.InteropServices;

namespace DonutCsharp
{
    // ... [Structures and Constants Mapping] ...

    class Program
    {
        [DllImport("donut.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int DonutCreate(ref DONUT_CONFIG config);

        [DllImport("donut.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int DonutDelete(ref DONUT_CONFIG config);

        [DllImport("donut.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr DonutError(int err);

        static void Main(string[] args)
        {
            DONUT_CONFIG config = new DONUT_CONFIG();

            config.input = args[0];
            config.output = args.Length >= 2 ? args[1] : "payload.bin";
            config.arch = DonutConstants.DONUT_ARCH_X84;
            // ... [Other Configs] ...

            int err = DonutCreate(ref config);

            if (err == DonutConstants.DONUT_ERROR_SUCCESS)
            {
                Console.WriteLine($"[+] Shellcode successfully generated at: {config.output}");
            }
            else
            {
                IntPtr errorPtr = DonutError(err);
                string errorMessage = Marshal.PtrToStringAnsi(errorPtr);
                Console.WriteLine($"[-] Donut Error: {errorMessage}");
            }

            DonutDelete(ref config);
        }
    }
}
```

<h2 id="disclaimer">4. Disclaimer</h2>

<p>We are not responsible for any misuse of this software or technique. Donut is provided as a demonstration of CLR Injection and in-memory loading through shellcode in order to provide red teamers a way to emulate adversaries and defenders a frame of reference for building analytics and mitigations. This inevitably runs the risk of malware authors and threat actors misusing it. However, we believe that the net benefit outweighs the risk. Hopefully that is correct. In the event EDR or AV products are capable of detecting Donut via signatures or behavioral patterns, we will not update Donut to counter signatures or detection methods. To avoid being offended, please do not ask.</p>

<h2 id="credits">5. Acknowledgments / Credits</h2>

<p>This fork's Custom CLR Host implementation was heavily inspired by the excellent research and Proof of Concept provided by the IBM X-Force Red team. Huge thanks to the creator of <a href="https://github.com/xforcered/Being-A-Good-CLR-Host">Being-A-Good-CLR-Host</a> for paving the way on stealthy, Fusion-less .NET execution.</p>

<p>We also thank the original creator of Donut, <a href="https://github.com/TheWover">TheWover</a>, for building the foundational framework that made this OPSEC evolution possible.</p>