#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <tchar.h>
#include <capstone.h>

#define STUB_SIZE_DEFAULT 64
#define STUB_SIZE_32 32
#define STUB_SIZE_64 64
#define MAX_PROCESSES 1024

const char* NtFunctions[] = {
    "NtOpenProcess",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtQuerySystemInformation",
    "NtAllocateVirtualMemory"
};

typedef enum {
    VERBOSITY_SUMMARY,
    VERBOSITY_STUB32,
    VERBOSITY_STUB64
} VerbosityLevel;

int numFunctions = sizeof(NtFunctions) / sizeof(NtFunctions[0]);

BOOL enable_debug_privilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

BYTE* load_clean_stub(const char* functionName) {
    HMODULE hClean = LoadLibraryExA("C:\\Windows\\System32\\ntdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hClean) return NULL;
    BYTE* addr = (BYTE*)GetProcAddress(hClean, functionName);
    if (!addr) {
        FreeLibrary(hClean);
        return NULL;
    }
    BYTE* stub = (BYTE*)malloc(STUB_SIZE_DEFAULT);
    memcpy(stub, addr, STUB_SIZE_DEFAULT);
    FreeLibrary(hClean);
    return stub;
}

void print_stub_disassembly(BYTE* stub, size_t size) {
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("Error initializing Capstone!\n");
        return;
    }

    count = cs_disasm(handle, stub, size, (uint64_t)stub, 0, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            printf("    0x%"PRIx64":\t", insn[j].address);
            for (int k = 0; k < insn[j].size; k++) {
                printf("%02x ", insn[j].bytes[k]);
            }
            printf("\t%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
        }
    }
    else {
        printf("Failed to disassemble the stub.\n");
    }

    cs_free(insn, count);
    cs_close(&handle);
}

BOOL match_process_name(DWORD pid, const char* name) {
    char baseName[MAX_PATH] = { 0 };
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return FALSE;
    HMODULE hMod;
    DWORD cbNeeded;
    if (EnumProcessModules(h, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleBaseNameA(h, hMod, baseName, sizeof(baseName));
    }
    CloseHandle(h);
    return _stricmp(baseName, name) == 0;
}

void scan_process(DWORD pid, BOOL jsonMode, FILE* jsonFile, VerbosityLevel verbosity) {
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        CloseHandle(hProc);
        return;
    }

    char procName[MAX_PATH] = { 0 };
    GetModuleBaseNameA(hProc, NULL, procName, MAX_PATH);

    printf("\n[*] PID %lu - %s\n", pid, procName);
    if (jsonFile) fprintf(jsonFile, "  \"%lu\": {\n    \"name\": \"%s\",\n    \"hooks\": {\n", pid, procName);

    for (int i = 0; i < numFunctions; i++) {
        const char* func = NtFunctions[i];
        BYTE* cleanStub = load_clean_stub(func);
        if (!cleanStub) continue;

        FARPROC procAddr = GetProcAddress(hNtdll, func);
        if (!procAddr) {
            free(cleanStub);
            continue;
        }

        BYTE remoteStub[STUB_SIZE_DEFAULT] = { 0 };
        SIZE_T bytesRead = 0;
        ReadProcessMemory(hProc, procAddr, remoteStub, STUB_SIZE_DEFAULT, &bytesRead);

        BOOL hooked = memcmp(cleanStub, remoteStub, STUB_SIZE_DEFAULT) != 0;

        printf("    [%s] %s\n", hooked ? "HOOKED" : "CLEAN", func);

        if (hooked && verbosity != VERBOSITY_SUMMARY) {
            printf("        Diff (%zu bytes):\n", (verbosity == VERBOSITY_STUB32) ? STUB_SIZE_32 : STUB_SIZE_64);
            print_stub_disassembly(remoteStub, (verbosity == VERBOSITY_STUB32) ? STUB_SIZE_32 : STUB_SIZE_64);
        }

        if (jsonFile) {
            fprintf(jsonFile, "      \"%s\": \"%s\"%s\n", func, hooked ? "HOOKED" : "CLEAN", (i == numFunctions - 1 ? "" : ","));
        }

        free(cleanStub);
    }

    if (jsonFile) fprintf(jsonFile, "    }\n  },\n");
    CloseHandle(hProc);
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s [process.exe | all] [--jsonfile output.json]\n", argv[0]);
        return 1;
    }

    enable_debug_privilege();

    BOOL scanAll = FALSE;
    BOOL jsonMode = FALSE;
    FILE* jsonFile = NULL;

    char* procNames[MAX_PROCESSES] = { 0 };
    int procCount = 0;

    VerbosityLevel verbosity = VERBOSITY_SUMMARY;

    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "all") == 0) {
            scanAll = TRUE;
        }
        else if (_stricmp(argv[i], "--verbosity") == 0 && i + 1 < argc) {
            i++;
            if (_stricmp(argv[i], "stub32") == 0) verbosity = VERBOSITY_STUB32;
            else if (_stricmp(argv[i], "stub64") == 0) verbosity = VERBOSITY_STUB64;
            else verbosity = VERBOSITY_SUMMARY;
        }
        else if (_stricmp(argv[i], "--jsonfile") == 0 && i + 1 < argc) {
            jsonMode = TRUE;
            jsonFile = NULL;
            errno_t err = fopen_s(&jsonFile, argv[++i], "w");
            if (err != 0) {
                printf("[-] Could not open output file.\n");
                return 1;
            }
            fprintf(jsonFile, "{\n");
        }
        else {
            procNames[procCount++] = argv[i];
        }
    }

    DWORD pids[MAX_PROCESSES];
    DWORD needed;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) {
        printf("[-] Could not enumerate processes.\n");
        return 1;
    }

    int total = needed / sizeof(DWORD);

    for (int i = 0; i < total; i++) {
        DWORD pid = pids[i];
        if (pid == 0) continue;

        if (scanAll) {
            scan_process(pid, jsonMode, jsonFile, verbosity);
        }
        else {
            for (int j = 0; j < procCount; j++) {
                if (match_process_name(pid, procNames[j])) {
                    scan_process(pid, jsonMode, jsonFile, verbosity);
                    break;
                }
            }
        }
    }

    if (jsonFile) {
        fseek(jsonFile, -3, SEEK_CUR); // remove trailing comma
        fprintf(jsonFile, "\n}\n");
        fclose(jsonFile);
    }

    return 0;
}
