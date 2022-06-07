#include "pch.h"
#include "Function.h"
#include "CSymbols.h"


SYMBOLS_DATA SymbolsData = { 0 };
ULONG SymbolsDataSize = sizeof(SYMBOLS_DATA) / sizeof(PVOID);


bool CallBack(char* Name, PVOID Address)
{    ///////////////////////////////////////////


	if (strcmp(Name, "PspActiveProcessLock") == 0)
	{
		SymbolsData.PspActiveProcessLock = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "ObFastReplaceObject") == 0)
	{
		SymbolsData.ObFastReplaceObject = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsReturnProcessPagedPoolQuota") == 0)
	{
		SymbolsData.PsReturnProcessPagedPoolQuota = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "ExDestroyHandle") == 0)
	{
		SymbolsData.ExDestroyHandle = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "MmCleanProcessAddressSpace") == 0)
	{
		SymbolsData.MmCleanProcessAddressSpace = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "MmDeleteProcessAddressSpace") == 0)
	{
		SymbolsData.MmDeleteProcessAddressSpace = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "MmGetFileNameForSection") == 0)
	{
		SymbolsData.MmGetFileNameForSection = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PspCidTable") == 0)
	{
		SymbolsData.PspCidTable = Address;
		SymbolsDataSize--;
	}



	else if (strcmp(Name, "ExfAcquirePushLockExclusive") == 0)
	{
		SymbolsData.ExfAcquirePushLockExclusive = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "ExfTryToWakePushLock") == 0)
	{
		SymbolsData.ExfTryToWakePushLock = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PspRemoveProcessFromJob") == 0)
	{
		SymbolsData.PspRemoveProcessFromJob = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PspDeleteLdt") == 0)
	{
		SymbolsData.PspDeleteLdt = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsReturnProcessNonPagedPoolQuota") == 0)
	{
		SymbolsData.PsReturnProcessNonPagedPoolQuota = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "AlpcpCleanupProcessViews") == 0)
	{
		SymbolsData.AlpcpCleanupProcessViews = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "ObDereferenceDeviceMap") == 0)
	{
		SymbolsData.ObDereferenceDeviceMap = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PspDereferenceQuotaBlock") == 0)
	{
		SymbolsData.PspDereferenceQuotaBlock = Address;
		SymbolsDataSize--;
	}

	////////////////////////////////////////////
	else if (strcmp(Name, "DbgkExitProcess") == 0)
	{
		SymbolsData.DbgkExitProcess = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpPostFakeThreadMessages") == 0)
	{
		SymbolsData.DbgkpPostFakeThreadMessages = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpPostFakeProcessCreateMessages") == 0)
	{
		SymbolsData.DbgkpPostFakeProcessCreateMessages = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkCopyProcessDebugPort") == 0)
	{
		SymbolsData.DbgkCopyProcessDebugPort = Address;
		SymbolsDataSize--;//ok
	}
	else if (strcmp(Name, "DbgkOpenProcessDebugPort") == 0)
	{
		SymbolsData.DbgkOpenProcessDebugPort = Address;
		SymbolsDataSize--;//ok
	}
	else if (strcmp(Name, "DbgkpSetProcessDebugObject") == 0)
	{
		SymbolsData.DbgkpSetProcessDebugObject = Address;
		SymbolsDataSize--;//ok
	}
	else if (strcmp(Name, "DbgkpMarkProcessPeb") == 0)
	{
	   SymbolsData.DbgkpMarkProcessPeb = Address;
	   SymbolsDataSize--;//ok
	}
	else if (strcmp(Name, "DbgkpWakeTarget") == 0)
	{
	   SymbolsData.DbgkpWakeTarget = Address;
	   SymbolsDataSize--;//ok
	}

	else if (strcmp(Name, "DbgkCreateThread") == 0)
	{
		SymbolsData.DbgkCreateThread = Address;
		SymbolsDataSize--;//ok
	}
	else if (strcmp(Name, "DbgkForwardException") == 0)
	{
		SymbolsData.DbgkForwardException = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkMapViewOfSection") == 0)
	{
		SymbolsData.DbgkMapViewOfSection = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkUnMapViewOfSection") == 0)
	{
	    SymbolsData.DbgkUnMapViewOfSection = Address;
	    SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpPostModuleMessages") == 0)
	{
		SymbolsData.DbgkpPostModuleMessages = Address;
		SymbolsDataSize--;
		MessageBoxA(NULL, "get DbgkpPostModuleMessages ok", "xxx", MB_ICONINFORMATION);
	}
	else if (strcmp(Name, "DbgkpQueueMessage") == 0)
	{
		SymbolsData.DbgkpQueueMessage = Address;
		SymbolsDataSize--;
	}

	else if (strcmp(Name, "DbgkpSendApiMessageLpc") == 0)
	{
		SymbolsData.DbgkpSendApiMessageLpc = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpSendErrorMessage") == 0)
	{
		SymbolsData.DbgkpSendErrorMessage = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpFreeDebugEvent") == 0)
	{
	   SymbolsData.DbgkpFreeDebugEvent = Address;
	   SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpSuspendProcess") == 0)
	{
	    SymbolsData.DbgkpSuspendProcess = Address;
	    SymbolsDataSize--;
	}
	else if (strcmp(Name, "KeResumeThread") == 0)
	{
		SymbolsData.KeResumeThread = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "KiDispatchException") == 0)
	{
		SymbolsData.KiDispatchException = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "ObDuplicateObject") == 0)
	{
		SymbolsData.ObDuplicateObject = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "ObFastDereferenceObject") == 0)
	{
		SymbolsData.ObFastDereferenceObject = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "ObFastReferenceObject") == 0)
	{
		SymbolsData.ObFastReferenceObject = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "ObFastReferenceObjectLocked") == 0)
	{
		SymbolsData.ObFastReferenceObjectLocked = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsCallImageNotifyRoutines") == 0)
	{
		SymbolsData.PsCallImageNotifyRoutines = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsSuspendThread") == 0)
	{
		SymbolsData.PsSuspendThread = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsResumeThread") == 0)
	{
	    SymbolsData.PsResumeThread = Address;
	    SymbolsDataSize--;
	}
	
	else if (strcmp(Name, "PsSynchronizeWithThreadInsertion") == 0)
	{
	   SymbolsData.PsSynchronizeWithThreadInsertion = Address;
	   SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkExitThread") == 0)
	{
		SymbolsData.DbgkExitThread = Address;
		SymbolsDataSize--;
	}

	else if (strcmp(Name, "DbgkClearProcessDebugObject") == 0)
	{
		SymbolsData.DbgkClearProcessDebugObject = Address;
		SymbolsDataSize--;
	}

	else if (strcmp(Name, "PspExitThread") == 0)
	{
		SymbolsData.PspExitThread = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PspTerminateAllThreads") == 0)
	{
		SymbolsData.PspTerminateAllThreads = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PspProcessDelete") == 0)
	{
		SymbolsData.PspProcessDelete = Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PspNotifyEnableMask") == 0)
	{
		SymbolsData.PspNotifyEnableMask = (PULONG)Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "KiCheckForKernelApcDelivery") == 0)
	{
		SymbolsData.KiCheckForKernelApcDelivery = (PULONG)Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsQuerySystemDllInfo") == 0)
	{
		SymbolsData.PsQuerySystemDllInfo = (PULONG)Address;
		SymbolsDataSize--;
	}
	//else if (strcmp(Name, "ExAcquireRundownProtection_0") == 0)
	//{
	//   SymbolsData.ExAcquireRundownProtection_0 = (PULONG)Address;
	//   SymbolsDataSize--;
	//}
	else if (strcmp(Name, "PsFreezeProcess") == 0)
	{
		SymbolsData.PsFreezeProcess = (PULONG)Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsThawProcess") == 0)
	{
		SymbolsData.PsThawProcess = (PULONG)Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "ZwFlushInstructionCache") == 0)
	{
		SymbolsData.ZwFlushInstructionCache = (PULONG)Address;
		SymbolsDataSize--;
	}
	else if (strcmp(Name, "LpcRequestWaitReplyPortEx") == 0)
	{
       SymbolsData.LpcRequestWaitReplyPortEx = (PULONG)Address;
	   SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsGetNextProcessThread") == 0)
	{
	   SymbolsData.PsGetNextProcessThread = (PULONG)Address;
	   SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkSendSystemDllMessages") == 0)
	{
	   SymbolsData.DbgkSendSystemDllMessages = (PULONG)Address;
	   SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsTestProtectedProcessIncompatibility") == 0)
	{
	   SymbolsData.PsTestProtectedProcessIncompatibility = (PULONG)Address;
	   SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsRequestDebugSecureProcess") == 0)
	{
	SymbolsData.PsRequestDebugSecureProcess = (PULONG)Address;
	SymbolsDataSize--;
	}
	

	if (SymbolsDataSize == 0)
	{
		return FALSE;
	}
	return TRUE;

}

#include <string>
using namespace std;
bool LoadSymbols(const char* symbolPath)
{
	CSymbols Symbols(symbolPath);

	if (Symbols.GetSymbolsAll(&CallBack) && SymbolsDataSize <= 2)
	{
		return TRUE;
	}
	string msg = std::to_string(SymbolsDataSize);
	MessageBoxA(NULL, msg.c_str(), "xxx", MB_ICONINFORMATION);


	if (!SymbolsData.DbgkCopyProcessDebugPort)
	{
		MessageBoxA(NULL, "DbgkCopyProcessDebugPort", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkpSetProcessDebugObject)
	{
		MessageBoxA(NULL, "DbgkpSetProcessDebugObject", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkSendSystemDllMessages)
	{
		MessageBoxA(NULL, "DbgkSendSystemDllMessages", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkpMarkProcessPeb)
	{
		MessageBoxA(NULL, "DbgkpMarkProcessPeb", "xxx", MB_ICONINFORMATION);
	}	
	if (!SymbolsData.DbgkpMarkProcessPeb)
	{
		MessageBoxA(NULL, "DbgkpMarkProcessPeb", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkpSendApiMessageLpc)
	{
		MessageBoxA(NULL, "DbgkpSendApiMessageLpc", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkpSendErrorMessage)
	{
		MessageBoxA(NULL, "DbgkpSendErrorMessage", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkpPostFakeThreadMessages)
	{
		MessageBoxA(NULL, "DbgkpPostFakeThreadMessages", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkpPostFakeProcessCreateMessages)
	{
		MessageBoxA(NULL, "DbgkpPostFakeProcessCreateMessages", "xxx", MB_ICONINFORMATION);
	}	
	if (!SymbolsData.DbgkpFreeDebugEvent)
	{
		MessageBoxA(NULL, "DbgkpFreeDebugEvent", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkExitProcess)
	{
		MessageBoxA(NULL, "DbgkExitProcess", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkExitThread)
	{
		MessageBoxA(NULL, "DbgkExitThread", "xxx", MB_ICONINFORMATION);
	}
	
	if (!SymbolsData.KeResumeThread)
	{
		MessageBoxA(NULL, "KeResumeThread", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkpPostModuleMessages)
	{
		MessageBoxA(NULL, "DbgkpPostModuleMessages", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkpSuspendProcess)
	{
		MessageBoxA(NULL, "DbgkpSuspendProcess", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.ObDuplicateObject)
	{
		MessageBoxA(NULL, "ObDuplicateObject", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.PsSuspendThread)
	{
		MessageBoxA(NULL, "PsSuspendThread", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.PsResumeThread)
	{
		MessageBoxA(NULL, "PsResumeThread", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.PsCallImageNotifyRoutines)
	{
		MessageBoxA(NULL, "PsCallImageNotifyRoutines", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.ObFastReferenceObject)
	{
		MessageBoxA(NULL, "ObFastReferenceObject", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.ObFastReferenceObjectLocked)
	{
		MessageBoxA(NULL, "ObFastReferenceObjectLocked", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.ObFastDereferenceObject)
	{
		MessageBoxA(NULL, "ObFastDereferenceObject", "xxx", MB_ICONINFORMATION);
	}

	if (!SymbolsData.KiCheckForKernelApcDelivery)
	{
		MessageBoxA(NULL, "KiCheckForKernelApcDelivery", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.PsFreezeProcess)
	{
		MessageBoxA(NULL, "PsFreezeProcess", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.PsThawProcess)
	{
		MessageBoxA(NULL, "PsThawProcess", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.PsGetNextProcessThread)
	{
		MessageBoxA(NULL, "PsGetNextProcessThread", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.PsQuerySystemDllInfo)
	{
		MessageBoxA(NULL, "PsQuerySystemDllInfo", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.MmGetFileNameForSection)
	{
		MessageBoxA(NULL, "MmGetFileNameForSection", "xxx", MB_ICONINFORMATION);
	}
	
	//if (!SymbolsData.ExAcquireRundownProtection_0)
	//{
	//	MessageBoxA(NULL, "ExAcquireRundownProtection_0", "xxx", MB_ICONINFORMATION);
	//}
	
	
	if (!SymbolsData.ZwFlushInstructionCache)
	{
		MessageBoxA(NULL, "ZwFlushInstructionCache", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.LpcRequestWaitReplyPortEx)
	{
		MessageBoxA(NULL, "LpcRequestWaitReplyPortEx", "xxx", MB_ICONINFORMATION);
	}

	if (!SymbolsData.DbgkMapViewOfSection)
	{
		MessageBoxA(NULL, "DbgkMapViewOfSection", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.DbgkUnMapViewOfSection)
	{
		MessageBoxA(NULL, "DbgkUnMapViewOfSection", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.PsTestProtectedProcessIncompatibility)
	{
		MessageBoxA(NULL, "PsTestProtectedProcessIncompatibility", "xxx", MB_ICONINFORMATION);
	}
	if (!SymbolsData.PsRequestDebugSecureProcess)
	{
		MessageBoxA(NULL, "PsRequestDebugSecureProcess", "xxx", MB_ICONINFORMATION);
	}
	
	
	return FALSE;
}