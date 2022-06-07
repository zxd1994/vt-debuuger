#include "KernelApi.h"
typedef PETHREAD(_fastcall* PSGETNEXTPROCESSTHREAD)(
	IN PEPROCESS Process,
	IN PETHREAD Thread
	);PSGETNEXTPROCESSTHREAD m_PsGetNextProcessThread = 0;
typedef NTSTATUS(_stdcall* NTOPENDIRECTORYOBJECT)(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes); NTOPENDIRECTORYOBJECT m_NtOpenDirectoryObject = 0;


PETHREAD myPsGetNextProcessThread
(
	IN PEPROCESS Process,
	IN PETHREAD Thread)
{
	if (!m_PsGetNextProcessThread)
	{

		PUCHAR p = (PUCHAR)GetKernelAddress("PsResumeProcess");
#ifdef _WIN64
		/* nt!PsResumeProcess + 0x64:
		 fffff800`042b8c64 488bce          mov     rcx, rsi
		 fffff800`042b8c67 e8ac7bbeff      call    nt!KeResumeThread(fffff800`03ea0818)
		 fffff800`042b8c6c 488bd6          mov     rdx, rsi
		 fffff800`042b8c6f 488bcd          mov     rcx, rbp
		 fffff800`042b8c72 e869f2eaff      call    nt!PsGetNextProcessThread(fffff800`04167ee0)*/

		if (!p)
		{
			return 0;
		}

		for (size_t i = 0; i < 0x100; i++)
		{
			if (*(p + 1) == 0x8b &&
				*(p + 2) == 0xd6 &&
				*(p + 4) == 0x8b &&
				*(p + 5) == 0xcd &&
				*(p + 6) == 0xe8)
			{
				INT offset = *(INT*)(p + 7);
				m_PsGetNextProcessThread=(PSGETNEXTPROCESSTHREAD)(offset + (INT_PTR)p + 11);
			}
			p++;
		}	
#else
		if (g_SystemData.WinVersion == 7601)
		{
			/*nt!PsResumeProcess + 0x4c:
			84117820 8b4508          mov     eax, dword ptr[ebp + 8]
			84117823 e8c059f5ff      call    nt!PsGetNextProcessThread(8406d1e8)
			84117828 8bd8            mov     ebx, eax
			8411782a 85db            test    ebx, ebx
			8411782c 75ea            jne     nt!PsResumeProcess + 0x44 (84117818)  Branch*/

			TZM tzm[5] = { {0xe8,0},{0x8b,-3},{0x45,-2},{0x08,-1} ,{0x8b,5} };
			m_PsGetNextProcessThread=(PSGETNEXTPROCESSTHREAD)FindMemory(p, 0x100, CMemroy::Call, tzm);
		}
#endif // _WIN64
		if (!m_PsGetNextProcessThread)
		{
			DbgPrint("Call PsGetNextProcessThread eeor\n");
			return 0;
		}
	}

#ifdef _WIN64
	return m_PsGetNextProcessThread(Process, Thread);
#else
	PETHREAD j_Thread;
	_asm
	{
		push Thread
		mov eax, Process
		call g_SystemData.PsGetNextProcessThread
		mov  j_Thread, eax
	}
	return j_Thread;
#endif // _WIN64

}

NTSTATUS  NtOpenDirectoryObject
(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes)
{

	if (!m_NtOpenDirectoryObject)
	{
		CKernelTable SSDT;
		m_NtOpenDirectoryObject =(NTOPENDIRECTORYOBJECT)SSDT.GetAddressFromName("NtOpenDirectoryObject");
		if (!m_NtOpenDirectoryObject)
		{
			DbgPrint("Call NtOpenDirectoryObject eeor\n");
			return STATUS_UNSUCCESSFUL;
		}
	}
	return m_NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
}

