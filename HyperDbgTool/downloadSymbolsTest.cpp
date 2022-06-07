#include <iostream>
#include <Windows.h>
#ifdef __cplusplus
extern "C"
{
#endif
#include "DbgHelp.h"//这里包含需要用C方式编译的头文件
#ifdef __cplusplus
}
#endif 
#pragma comment(lib , "DbgHelp.lib")
#pragma comment(lib , "ntdll.lib")
#define STATUS_UNSUCCESSFUL (0xC0000001L)
#define  SystemModuleInformation 11
#define STATUS_SUCCESS        0x00000000 
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

extern "C" NTSTATUS __stdcall  ZwQuerySystemInformation(
    __in       ULONG SystemInformationClass,
    __inout    PVOID SystemInformation,
    __in       ULONG SystemInformationLength,
    __out_opt  PULONG ReturnLength
);


typedef BOOL(__stdcall* IMAGEUNLOAD)(
    __in  PLOADED_IMAGE LoadedImage
    );
IMAGEUNLOAD pImageUnload;
int FuncCount = 0;
typedef PLOADED_IMAGE(__stdcall* IMAGELOAD)(
    __in  PSTR DllName,
    __in  PSTR DllPath
    );
IMAGELOAD pImageLoad;


typedef BOOL(__stdcall* SYMGETSYMBOLFILE)(
    __in_opt HANDLE hProcess,
    __in_opt PCSTR SymPath,
    __in PCSTR ImageFile,
    __in DWORD Type,
    __out_ecount(cSymbolFile) PSTR SymbolFile,
    __in size_t cSymbolFile,
    __out_ecount(cDbgFile) PSTR DbgFile,
    __in size_t cDbgFile
    );
SYMGETSYMBOLFILE pSymGetSymbolFile;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
    ULONG Unknow1;
    ULONG Unknow2;
    ULONG Unknow3;
    ULONG Unknow4;
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT NameLength;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;//内核中以加载的模块的个数
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

PLOADED_IMAGE pli;
typedef struct _tagSysModuleList {          //模块链结构
    ULONG ulCount;
    SYSTEM_MODULE_INFORMATION smi[2];
} MODULES, * PMODULES;


//-------------------------------------------------------------------------
//保存所有内核函数的一个结构
//-------------------------------------------------------------------------
typedef struct _KERNELFUNC_ADDRESS_INFORMATION {
    ULONG ulAddress;
    CHAR FuncName[50];
}KERNELFUNC_ADDRESS_INFORMATION, * PKERNELFUNC_ADDRESS_INFORMATION;

typedef struct _WIN32KFUNCINFO {          //PNTOSFUNCINFO
    ULONG ulCount;
    KERNELFUNC_ADDRESS_INFORMATION Win32KFuncInfo[1];
} WIN32KFUNCINFO, * PWIN32KFUNCINFO;

PWIN32KFUNCINFO FuncAddressInfo;




HANDLE hProcess;
BOOLEAN InitSymHandler()
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

    Sleep(3000);

    hProcess = GetCurrentProcess();//获取当前进程

    //设置搜索参数：
    //SYMOPT_CASE_INSENSITIVE 该选项使得所有对符号名的搜索区分大小写
    //

    SymSetOptions(SYMOPT_CASE_INSENSITIVE | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);

    //设置搜索路径
    //程序会把win32k的pdb符号文件下载到这个目录Path
    SymSetSearchPath(hProcess, Path);

    //这个是不是很眼熟？
    //SRV*d:\localsymbols*http://msdl.microsoft.com/download/symbols
    sprintf(SymPath, "SRV*%s*%s", Path, SymbolsUrl);

    //在这里初始化
    if (!SymInitialize(hProcess,
        SymPath,
        TRUE))
    {
        printf("SymInitialize failed %d \n", GetLastError());
        return FALSE;
    }//初始化符号
    return TRUE;
}

ULONG GetKernelInfo(char* lpKernelName, ULONG* ulBase, ULONG* ulSize)
{
    DWORD    dwsize;
    DWORD    dwSizeReturn;
    PUCHAR    pBuffer = NULL;

    PMODULES    pSmi = NULL;
    NTSTATUS    ntStatus = STATUS_UNSUCCESSFUL;

    //明明是内核的api，怎么能在驱动层调用呢？
    //ntdll!ZwQuerySystemInformation 
    //ntdll!NtQuerySystemInformation
    //所以，我们在这里调用的是ntdll的函数，而不是ntoskrnel.exe
    ntStatus = ZwQuerySystemInformation(
        SystemModuleInformation,
        pSmi,
        0,
        &dwSizeReturn
    );
    if (ntStatus != STATUS_INFO_LENGTH_MISMATCH)
    {
        return 0;
    }
    dwsize = dwSizeReturn * 2;
    pSmi = (PMODULES)new char[dwsize];
    if (pSmi == NULL)
    {
        return 0;
    }

    ntStatus = ZwQuerySystemInformation(
        SystemModuleInformation,
        pSmi,
        dwsize,
        &dwSizeReturn
    );
    if (ntStatus != STATUS_SUCCESS)
    {
        return 0;
    }
    for (int i = 0; i < pSmi->ulCount; i++)
    {
        //循环从链表对比
        if (_stricmp(pSmi->smi[i].Module->ImageName, lpKernelName) == 0)
        {
            printf("found %08X %X\,,%s,,,r\n", pSmi->smi[i].Module->Base, pSmi->smi[i].Module->Size, pSmi->smi[i].Module->ImageName);
            *ulBase = (ULONG)pSmi->smi[i].Module->Base;
            *ulSize = pSmi->smi[i].Module->Size;
            break;
        }
    }
    delete pSmi;

    return TRUE;
}


BOOLEAN LoadSymModule(
    char* ImageName,
    DWORD ModuleBase)
{
    DWORD64 tmp;
    char    SymFileName[MAX_PATH] = { 0 };
    BOOL bRetOK = FALSE;

    HINSTANCE hmod = LoadLibraryA("Imagehlp.dll");
    if (!hmod)
        return FALSE;

    pImageLoad = (IMAGELOAD)GetProcAddress(hmod, "ImageLoad");
    pImageUnload = (IMAGEUNLOAD)GetProcAddress(hmod, "ImageUnload");
    if (!pImageLoad ||
        !pImageUnload)
        return FALSE;

    pli = pImageLoad(ImageName, NULL);
    if (pli == NULL)
    {
        printf("cannot get loaded module of %s \n", ImageName);
        return FALSE;
    }
    printf("ModuleName:%s:%08x\n", pli->ModuleName, pli->SizeOfImage);

    HINSTANCE hDbgHelp = LoadLibraryA("dbghelp.dll");
    if (!hDbgHelp)
        return FALSE;

    pSymGetSymbolFile = (SYMGETSYMBOLFILE)GetProcAddress(hDbgHelp, "SymGetSymbolFile");
    if (!pSymGetSymbolFile) {
        printf("pSymGetSymbolFile() failed %X\r\n", pSymGetSymbolFile);
        return FALSE;
    }
    //欲解析符号前,使用SymGetSymbolFile来取得符号文件,如果搜索路径没有这个文件,那么将从微软服务器下载win32k的pdb,然后调用SymLoadModule64加载解析它咯
    if (pSymGetSymbolFile(hProcess,
        NULL,
        pli->ModuleName,
        sfPdb,
        SymFileName,
        MAX_PATH,
        SymFileName,
        MAX_PATH))
    {
        //然后调用SymLoadModule64加载它咯
        tmp = SymLoadModule64(hProcess,
            pli->hFile,
            pli->ModuleName,
            NULL,
            (DWORD64)ModuleBase,
            pli->SizeOfImage);
        if (tmp)
        {
            bRetOK = TRUE;
        }
    }
    //加载了，就要卸载
    //申请了内存，就要释放一样的道理
    //学java的同学要注意。
    pImageUnload(pli);
    return bRetOK;
}


BOOLEAN EnumSyms(
    char* ImageName,
    DWORD ModuleBase,
    PSYM_ENUMERATESYMBOLS_CALLBACK EnumRoutine,
    PVOID Context)
{
    BOOLEAN bEnum;

    //首先加载符号模块
    if (!LoadSymModule(ImageName, ModuleBase))
    {
        printf("cannot load symbols ,error: %d \n", GetLastError());
        return FALSE;
    }
    //解析符号
    bEnum = SymEnumSymbols(hProcess,
        ModuleBase,
        NULL,
        EnumRoutine, //有一个回调
        Context);
    if (!bEnum)
    {
        printf("cannot enum symbols ,error: %d \n", GetLastError());
    }
    return bEnum;
}


//这个就是回调函数
BOOLEAN CALLBACK EnumSymRoutine(
    PSYMBOL_INFO psi,
    ULONG     SymSize,
    PVOID     Context)
{
    if (_stricmp(psi->Name, "NtUserFindWindowEx") == 0)
    {
        /*
            typedef struct _WIN32KFUNCINFO {          //PNTOSFUNCINFO
            ULONG ulCount;
            KERNELFUNC_ADDRESS_INFORMATION Win32KFuncInfo[1];
        } WIN32KFUNCINFO, *PWIN32KFUNCINFO;

        PWIN32KFUNCINFO FuncAddressInfo;
        */
        FuncAddressInfo->Win32KFuncInfo[FuncCount].ulAddress = (ULONG)psi->Address;
        strcat(FuncAddressInfo->Win32KFuncInfo[FuncCount].FuncName, psi->Name);
        FuncCount++;
    }
    if (_stricmp(psi->Name, "NtUserQueryWindow") == 0)
    {
        FuncAddressInfo->Win32KFuncInfo[FuncCount].ulAddress = (ULONG)psi->Address;
        strcat(FuncAddressInfo->Win32KFuncInfo[FuncCount].FuncName, psi->Name);
        FuncCount++;
    }
    FuncAddressInfo->ulCount = FuncCount;
    return TRUE;
}


int downloadSymbolsTest()
{
    ULONG ulBase;
    ULONG ulSize;
    //先初始化符号
    if (InitSymHandler())
    {
        if (GetKernelInfo("\\SystemRoot\\System32\\ntoskrnl.exe", &ulBase, &ulSize))
        {

            FuncAddressInfo = (PWIN32KFUNCINFO)VirtualAlloc(0, (sizeof(WIN32KFUNCINFO) + sizeof(KERNELFUNC_ADDRESS_INFORMATION)) * 10, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (FuncAddressInfo)//分配成功的话
            {
                memset(FuncAddressInfo, 0, (sizeof(WIN32KFUNCINFO) + sizeof(KERNELFUNC_ADDRESS_INFORMATION)) * 10);

                //到这里，开始枚举（并且保存到结构体）
                EnumSyms("ntoskrnl.exe", ulBase, (PSYM_ENUMERATESYMBOLS_CALLBACK)EnumSymRoutine, NULL);

                //要接触加载
                SymUnloadModule64(GetCurrentProcess(), ulBase);

                //清理
                SymCleanup(GetCurrentProcess());

                for (int i = 0; i < FuncAddressInfo->ulCount; i++)
                {
                    //打印测试
                    printf("%s[0x%08X]\r\n", FuncAddressInfo->Win32KFuncInfo[i].FuncName, FuncAddressInfo->Win32KFuncInfo[i].ulAddress);
                }
                //传到内核（用到我们学到的通信了吧）
                //CallDriver(WIN32K_FUNCTION,FuncAddressInfo,(sizeof(WIN32KFUNCINFO)+sizeof(KERNELFUNC_ADDRESS_INFORMATION))*10);
            }
        }
    }
    getchar();
    return 0;
}