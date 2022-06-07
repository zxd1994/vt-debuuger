#pragma once
#include <Windows.h>
#include <winsvc.h>
#define CTL_CODE( DeviceType, Function, Method, Access ) ( ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define FILE_DEVICE_UNKNOWN             0x00000022
#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3
#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe

class CLoadDriver
{

#define  符号名 L"\\\\.\\HyperDbg"
private:

	HANDLE m_hDevice;

public:

	BOOLEAN Load(const WCHAR* DriverName)
	{
		WCHAR DriverPatch[MAX_PATH];
		
		if (!GetCurrentDirectory(sizeof(DriverPatch), DriverPatch))
		{
			return FALSE;
		}
		wcscat_s(DriverPatch, L"\\");
		wcscat_s(DriverPatch, DriverName);

		SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		SC_HANDLE hService = CreateService(hSCManager, DriverName,
			DriverName, SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
			SERVICE_ERROR_IGNORE, DriverPatch, NULL, NULL, NULL, NULL, NULL);

		

		if (hService == 0)
		{
			hService = OpenService(hSCManager, DriverName, SERVICE_ALL_ACCESS);
		}
		bool boole = StartService(hService, 0, NULL);

		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
			if (!boole)
			{
				if (GetLastError()==1056)//驱动已经运行
				{
					return FALSE;
				}
			}
			
			m_hDevice = CreateFile(符号名,
				GENERIC_READ | GENERIC_WRITE,
				0,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			if (m_hDevice == INVALID_HANDLE_VALUE)
			{
				UnLoad(DriverName);
             return FALSE;
			}
			else
			{
				return TRUE;
			}
	}
	BOOL UnLoad(const WCHAR* lpName)
	{
		CloseHandle(m_hDevice);
		SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		SC_HANDLE hService = OpenService(hSCManager, lpName, SERVICE_ALL_ACCESS);
	
		SERVICE_STATUS ss;
		ControlService(hService, SERVICE_CONTROL_STOP, &ss);
		BOOLEAN boole = DeleteService(hService);
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return boole;
	}

	//CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
	BOOL DeviceControl(DWORD ControlCode, LPVOID lpInBuffer, IN DWORD InBufferSize,OUT LPVOID lpOutBuffer, DWORD OutBufferSize, LPDWORD lpBytesReturned )
	{
	     return	DeviceIoControl(m_hDevice, ControlCode, lpInBuffer, InBufferSize, lpOutBuffer, OutBufferSize, lpBytesReturned, 0);
	}

};

