#include "Windows.h"
#include "winternl.h"
#include "stdio.h"

#pragma comment(lib, "ntdll")

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Length;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	BYTE reserved[64];
} _RTL_USER_PROCESS_INFORMATION, *PRL_USER_PROCESS_INFORMATION;

extern "C" {
	
	NTSTATUS NTAPI RtlCreateUserProcess(
		__in PUNICODE_STRING NtImagePathName,
		__in ULONG Attributes,
		__in PVOID ProcessParameters,
		__in_opt PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
		__in_opt PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		__in_opt HANDLE ParentProcess,
		__in BOOLEAN InheritHandles,
		__in_opt HANDLE DebugPort,
		__in_opt HANDLE TokenHandle,
		__out PRL_USER_PROCESS_INFORMATION ProcessInformation
	);
	NTSTATUS NTAPI RtlCreateProcessParameters(
		__deref_out PVOID* pProcessParameters,
		__in PUNICODE_STRING ImagePathName,
		__in_opt PUNICODE_STRING DllPath,
		__in_opt PUNICODE_STRING CommandLine,
		__in_opt PVOID Enviroment,
		__in_opt PUNICODE_STRING WindowTitle,
		__in_opt PUNICODE_STRING DesktopInfo,
		__in_opt PUNICODE_STRING ShellInfo,
		__in_opt PUNICODE_STRING RuntimeData
	);
}

int Error(NTSTATUS status) {
	printf("Error (status=0x%00X)\n", status);
	return 0;
}

int wmain(int argc, const wchar_t* argv[]) {
	if (argc < 2) {
		printf("Usage: nativerun <image path> [parameters] \n");
		return 0;
	}

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, argv[1]);

	_RTL_USER_PROCESS_INFORMATION info;
	PVOID params;
	auto status = RtlCreateProcessParameters(&params, &name, nullptr, nullptr, &name,
		nullptr,
		nullptr,
		nullptr,
		nullptr);
	if (!NT_SUCCESS(status))
		return Error(status);
	status = RtlCreateUserProcess(&name, 0, params, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &info);
	if (!NT_SUCCESS(status))
		return Error(status);
	printf("Process 0x%p created!\n", info.ClientId.UniqueProcess);

	ResumeThread(info.Thread);
	printf("Resumed Thread 0x%p", info.Thread);
	return 0;
}