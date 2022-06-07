#include "pch.h"
#include "CSymbols.h"

#pragma comment(lib,"dbghelp.lib")

BOOLEAN CSymbols::InitSymHandler1()
{
	HANDLE hfile;
	char Path[MAX_PATH] = { 0 };
	char FileName[MAX_PATH] = { 0 };
	char SymPath[MAX_PATH * 2] = { 0 };
	char* SymbolsUrl = "http://msdl.microsoft.com/download/symbols";


	if (!GetCurrentDirectoryA(MAX_PATH, Path))//获取当前目录
	{
		printf("cannot get current directory \n");
		return FALSE;
	}

	strcat(Path, "\\Symbols");//比如:C:\Symbols
	CreateDirectoryA(Path, NULL);//创建目录

	//首先创建一个目录 symsrv.yes文件，symsrv.dll会检查，没有就会弹出一个对话框要求你点确认

	strcpy(FileName, Path);
	strcat(FileName, "\\symsrv.yes");
	printf("%s \n", FileName);

	hfile = CreateFileA(FileName,
		FILE_ALL_ACCESS,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		printf("create or open file error: 0x%X \n", GetLastError());
		return FALSE;

	}
	CloseHandle(hfile);

	//Sleep(3000);

	HANDLE hProcess = GetCurrentProcess();//获取当前进程

	//设置搜索参数：
	//SYMOPT_CASE_INSENSITIVE 该选项使得所有对符号名的搜索区分大小写
	//

	SymSetOptions(SYMOPT_CASE_INSENSITIVE | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);

	//这个是不是很眼熟？
	//SRV*d:\localsymbols*http://msdl.microsoft.com/download/symbols
	sprintf(SymPath, "SRV*%s*%s", Path, SymbolsUrl);
	strcpy(SymPath, m_SymbolsPatch);

	//在这里初始化
	if (!SymInitialize(hProcess,
		SymPath,
		TRUE))
	{
		printf("SymInitialize failed %d \n", GetLastError());
		return FALSE;
	}//初始化符号

	//设置搜索路径
    //程序会把win32k的pdb符号文件下载到这个目录Path
	if (!SymSetSearchPath(hProcess, SymPath))
	{
		DWORD dwerr = GetLastError();
		printf("SymSetSearchPath failed %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
//SRV*C:\Symbols* http://msdl.microsoft.com/download/symbols;D:\vt\HyperHide-master\x64\Release


//BOOL LoadSymModule(HANDLE hProc, HMODULE hDll)
//{
//	CHAR szFile[MAX_PATH], SymFile[MAX_PATH];
//
//	MODULEINFO ModInfo;
//
//	GetModuleFileNameA(hDll, szFile, sizeof(szFile) / sizeof(szFile[0]));
//
//	GetModuleInformation(hProc, hDll, &ModInfo, sizeof(ModInfo));
//
//	if (SymGetSymbolFile(hProc, NULL, szFile, sfPdb, SymFile, MAX_PATH, SymFile, MAX_PATH))
//	{
//		return (SymLoadModule64(hProc, NULL, szFile, NULL, (ULONG_PTR)ModInfo.lpBaseOfDll, ModInfo.SizeOfImage) != 0);
//	}
//
//	return FALSE;
//}


CSymbols::CSymbols()
{
	m_ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
}
CSymbols::CSymbols(const char* SymbolsPatch)
{
	m_ZwQuerySystemInformation =(ZWQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
	m_SymbolsPatch = SymbolsPatch;

	Module_INFO Module;
		
		if (!GetKernelModuleInfo(&Module))
		{
			MessageBox(0, L"GetKernelModuleInfo error!", L"", 0);	
		}
		DWORD Options = SymGetOptions();
		Options = Options | SYMOPT_DEBUG;
		SymSetOptions(Options);
		m_hProcess = GetCurrentProcess();

		//BOOL bRet = SymInitialize(m_hProcess, 0, FALSE);
		//if (!bRet)
		//{
		//	MessageBox(0, L"SymInitialize error!", L"", 0);
		//	return ;	
		//}

		if (!InitSymHandler1())
		{
			MessageBox(0, L"SymInitialize error!", L"", 0);
			return;
		}
		
		if (m_SymbolsPatch==0)
		{
			MessageBox(0,L"m_SymbolsPatch error",L"",0);
			return ;
		}

		if (!SymSetSearchPath(m_hProcess, m_SymbolsPatch))
		{
			MessageBox(0,L"SymSetSearchPath error!",L"",0);
			return ;
		}

		HMODULE hDll = LoadLibraryEx(TEXT("ntoskrnl.exe"), NULL, DONT_RESOLVE_DLL_REFERENCES);
		char szFile[MAX_PATH], SymFile[MAX_PATH] = {""}; char SymFile1[MAX_PATH] = { "" };
		//MODULEINFO ModInfo;
		GetModuleFileNameA(hDll, szFile, sizeof(szFile) / sizeof(szFile[0]));

		char currentDir[260];
		GetCurrentDirectoryA(260, currentDir);
		//char szcurrFile[MAX_PATH];
		//GetModuleFileNameA(NULL, szcurrFile, sizeof(szcurrFile) / sizeof(szcurrFile[0]));
		//HANDLE hcurr = GetModuleHandleA(szcurrFile);
		//char SymFile[MAX_PATH] = {""}; char SymFile1[MAX_PATH] = { "" };
		if (!SymGetSymbolFile(m_hProcess, NULL, szFile, sfPdb, SymFile, MAX_PATH, SymFile1, MAX_PATH))
		{
			int err = GetLastError();
			char msg[260];
			sprintf(msg, "SymGetSymbolFile error:%d", err);
			MessageBoxA(0, msg, "", 0);
			return;
		}

		char FileName[MAX_PATH];
		GetSystemDirectoryA(FileName, sizeof(FileName));
		strcat_s(FileName, "\\");
		strcat_s(FileName, Module.KernelName);
		HANDLE hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile==INVALID_HANDLE_VALUE)
		{
			MessageBox(0,L"CreateFileA error!",L"",0);
			return ;
		}
		DWORD dwfilesize = GetFileSize(hFile, NULL);
		
		m_BaseOfDll = SymLoadModule64(m_hProcess, hFile, FileName, NULL, (DWORD64)Module.KernelBass, dwfilesize);
		CloseHandle(hFile);
		if (m_BaseOfDll == 0)
		{
			//printf("SymLoadModule64:%d\n", GetLastError());
			MessageBox(0,L"SymLoadModule64 error!",L"",0);
			return ;
		}


}

CSymbols::~CSymbols()
{
	SymUnloadModule64(m_hProcess, m_BaseOfDll);
	SymCleanup(m_hProcess);
}

BOOLEAN CSymbols::GetKernelModuleInfo(
	PModule_INFO ModuleInfo)
{
	ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = m_ZwQuerySystemInformation;
	ULONG  RetLenth=0;
	PSYSTEM_MODULE_INFORMATION Buffer=0 ;
	NTSTATUS status;
	
	do
	{
		Buffer =(PSYSTEM_MODULE_INFORMATION)malloc(RetLenth);
		status=ZwQuerySystemInformation(11, Buffer, RetLenth, &RetLenth);

		if (!NT_SUCCESS(status)&& status != 0xC0000004L)
		{
			free(Buffer);
			return FALSE;
		}

	} while (status== 0xC0000004L);
	
	ModuleInfo->KernelBass = Buffer->Module[0].Base;
	ModuleInfo->KernelSize = Buffer->Module[0].Size;
	strcpy_s(ModuleInfo->KernelPatch, Buffer->Module[0].ImageName);
	strcpy_s(ModuleInfo->KernelName, Buffer->Module[0].ImageName+ Buffer->Module[0].ModuleNameOffset);
	free(Buffer);
	return TRUE;
}


BOOL CALLBACK CSymbols::EnumAllSymbolsCallBack(
	PSYMBOL_INFO pSymInfo,
	ULONG SymbolSize,
	PVOID UserContext)
{
	return ((ENUMSYMBOLSCALLBACK)UserContext)(pSymInfo->Name,(PVOID) pSymInfo->Address);	
}


BOOLEAN CSymbols::GetSymbolsAll(ENUMSYMBOLSCALLBACK callback)
{
	if (SymEnumSymbols(m_hProcess, m_BaseOfDll, 0, &EnumAllSymbolsCallBack, callback))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}





