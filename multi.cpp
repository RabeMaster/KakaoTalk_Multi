#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <string.h>
#include <vector>

#define SystemExtendedHandleInformation 64
#define ObjectNameInformation 1
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Reserved;
	PVOID Object; // move
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ACCESS_MASK GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_EXTENDED_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_EXTENDED_HANDLE_INFORMATION, *PSYSTEM_EXTENDED_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI *NtQuerySystemInformation_t) (SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI *NtQueryObject_t) (HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

bool Bypass(DWORD hPid);
bool UpdateProcess(std::vector<DWORD>& arr);

int main()
{
	system("Color 0F");
	SetConsoleTitle("KakaoTalk Multi");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15); //White

	std::cout << "Running..." << std::endl;

	std::vector<DWORD> PidList;
	while (true)
	{
		PidList.clear();
		UpdateProcess(PidList);
		for (int i = 0; i < PidList.size(); i++)
			if (Bypass(PidList.at(i)))
				std::cout << "Pid : " << PidList.at(i) << " - Patched" << std::endl;
		Sleep(1000);
	}
	return 0;
}

bool Bypass(DWORD hPid)
{
	HINSTANCE hInst = GetModuleHandle("ntdll.dll");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, hPid);

	NTSTATUS status;
	CHAR* buffer;
	ULONG bufferSize = 0x10000;
	PSYSTEM_EXTENDED_HANDLE_INFORMATION handles;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX pEntry;
	ULONG i;
	HANDLE savedHandle = 0;

	NtQuerySystemInformation_t _NtQuerySystemInformation;
	NtQueryObject_t _NtQueryObject;

	_NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hInst, "NtQuerySystemInformation");
	_NtQueryObject = (NtQueryObject_t)GetProcAddress(hInst, "NtQueryObject");

	buffer = (char*)calloc(bufferSize, sizeof(char));

	while ((status = _NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation,
		buffer,
		bufferSize,
		NULL)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		free(buffer);
		bufferSize *= 2;
		buffer = (char*)calloc(bufferSize, sizeof(char));
	}
	if (!NT_SUCCESS(status))
	{
		free(buffer);
		return false;
	}

	handles = (PSYSTEM_EXTENDED_HANDLE_INFORMATION)buffer;
	for (i = 0; i < handles->NumberOfHandles; i++)
	{
		pEntry = &(handles->Handles[i]);
		if (pEntry->UniqueProcessId != (HANDLE)hPid) continue;
		if (pEntry->ObjectTypeIndex == 19) //semapore
		{
			wchar_t nameBuf[1024];
			DWORD length;
			HANDLE hTargetHandle;
			bool stat = DuplicateHandle(hProcess, (HANDLE)pEntry->HandleValue, GetCurrentProcess(), &hTargetHandle, 0, 0, DUPLICATE_SAME_ACCESS);
			if (!stat) continue;
			status = _NtQueryObject((HANDLE)hTargetHandle, (OBJECT_INFORMATION_CLASS)ObjectNameInformation, nameBuf, 1024, &length);
			if (!NT_SUCCESS(status)) continue;
			
			if (wcsstr(nameBuf + 4, L"97C4DDD9") != 0)
			{
				HANDLE handle;
				DuplicateHandle(hProcess, (HANDLE)pEntry->HandleValue, GetCurrentProcess(), &handle, 0, 0, DUPLICATE_CLOSE_SOURCE);
				CloseHandle(handle); //delete

				CloseHandle(hTargetHandle);
				CloseHandle(hProcess);
				return true;
			}
			CloseHandle(hTargetHandle);
		}
	}
	CloseHandle(hProcess);
	return false;
}

bool UpdateProcess(std::vector<DWORD>& arr)
{
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hModule == INVALID_HANDLE_VALUE) return false;

	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(PROCESSENTRY32);

	do
	{
		if (!strcmp(processInfo.szExeFile, "KakaoTalk.exe"))
		{
			arr.push_back(processInfo.th32ProcessID);
			continue;
		}
	} while (Process32Next(hModule, &processInfo));

	return false;
}