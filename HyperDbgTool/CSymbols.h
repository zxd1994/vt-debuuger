#pragma once

#include "ntdll.h"

typedef struct _Address_Name
{
IN	char  Name[MAX_PATH];
PVOID Address;
	
}Address_Name,*PAddress_Name;


typedef struct _Module_INFO
{
		char KernelName[MAX_PATH];
		char KernelPatch[MAX_PATH];
		PVOID KernelBass;
		ULONG KernelSize;
}Module_INFO,*PModule_INFO;

typedef bool (*ENUMSYMBOLSCALLBACK)(char* Name, PVOID Address);
class CSymbols
{
public:
	CSymbols(const char* SymbolsPatch);
	CSymbols();
	~CSymbols();

	BOOLEAN GetKernelModuleInfo(OUT PModule_INFO ModuleInfo);
	BOOLEAN GetSymbolsAll(ENUMSYMBOLSCALLBACK callback);


private:
	BOOLEAN CSymbols::InitSymHandler1();

protected:
	HANDLE m_hProcess;
	DWORD64  m_BaseOfDll;
	
	const char* m_SymbolsPatch=0;//"E:\\symbols"
	char* m_Name;
	PVOID* m_Address=0;
	ZWQUERYSYSTEMINFORMATION m_ZwQuerySystemInformation;

	static BOOL CALLBACK EnumAllSymbolsCallBack(
		PSYMBOL_INFO pSymInfo,
		ULONG SymbolSize,
		PVOID UserContext);
	
};




