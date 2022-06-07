#pragma once
#include "CFunction.h"
#include "CPeModule.h"
#include "GlobalData.h"

//内存
PVOID RtlAllocMemroy(POOL_TYPE PoolType,ULONG_PTR NumberOfBytes,INT16 FillData)
{
	PVOID Memroy =ExAllocatePool(PoolType, NumberOfBytes);
	if (!Memroy)
	{
		return 0;
	}
	RtlFillMemory(Memroy, NumberOfBytes, FillData);
	return Memroy;
}

// 功能类

PVOID GetKernelAddress(char* FunName)
{
	UNICODE_STRING FunNameUnicode;
	ANSI_STRING  as;
	RtlInitAnsiString(&as, FunName);
	RtlAnsiStringToUnicodeString(&FunNameUnicode, &as, TRUE);
	return MmGetSystemRoutineAddress(&FunNameUnicode);
}
void Sleep(LONG msec)
{
	LARGE_INTEGER li;
	li.QuadPart = -10 * 1000;
	li.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &li);
}

UINT8  SetCurrentThreadMode(
	IN PETHREAD EThread, 
	IN UINT8 NewMode)
	{
	    // 保存原先模式
	    UINT8 PreviousMode = *((PUINT8)EThread + g_SystemData.PreviousModeOffset);
	    // 修改为WantedMode
	    *((PUINT8)EThread + g_SystemData.PreviousModeOffset) = NewMode;
	    return PreviousMode;
	}
BOOLEAN IsUnicodeString(
	IN PUNICODE_STRING us)
{
	BOOLEAN bOk = FALSE;

	__try
	{
		if (us->Length > 0 &&
			us->Buffer &&
			MmIsAddressValid(us->Buffer) &&
			MmIsAddressValid(&us->Buffer[us->Length / sizeof(WCHAR) - 1]))
		{
			bOk = TRUE;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		bOk = FALSE;
	}

	return bOk;
}

ULONG GetSystemStartTime()
{
	LARGE_INTEGER la;
	ULONG MyInc;
	MyInc = KeQueryTimeIncrement(); //返回滴答数
	KeQueryTickCount(&la);
	la.QuadPart *= MyInc;
	la.QuadPart /= 10000;
	return la.LowPart;
}


//NT路径转换DOS路径
BOOLEAN NtFileNameToDosFileName(IN PUNICODE_STRING us, OUT WCHAR* ws)
{//文件被删除则会失败
	
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	PFILE_OBJECT FileObject = NULL;
	POBJECT_NAME_INFORMATION pObjectNameInfo=0;
	BOOLEAN boole= FALSE;
	
	
	InitializeObjectAttributes(&ObjectAttributes, us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	if (NT_SUCCESS(ZwOpenFile(&hFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT)))
	{
		if (NT_SUCCESS(ObReferenceObjectByHandle(hFile, FILE_READ_ATTRIBUTES, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL)))
		{
			if (NT_SUCCESS(IoQueryFileDosDeviceName(FileObject, &pObjectNameInfo)))
			{
				wcscpy(ws, pObjectNameInfo->Name.Buffer);
				boole= TRUE;
			}
		}
	}
	if (pObjectNameInfo)
	{
		ExFreePool(pObjectNameInfo);
	}

	if (FileObject)
	{
		ObDereferenceObject(FileObject);
	}

	if (hFile)
	{
		ZwClose(hFile);
	}



	return boole;
}
