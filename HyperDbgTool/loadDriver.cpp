#include "loadDriver.h"
#include "mylog.h"
#include <Shlwapi.h>

bool installDriver(LPCWSTR serviceName, LPCWSTR displayName, LPCWSTR driverFilePath)//安装
{
	bool bok = false;
	char chServiceName[260];
	SHTCharToAnsi(serviceName, chServiceName, 260);
	SC_HANDLE schSCManager;
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager)
	{
		SC_HANDLE schService = CreateService(schSCManager,
			serviceName,
			displayName,
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER, //创建的服务类型1为驱动服务
			SERVICE_DEMAND_START, //用于当有进程调用StartService 函数时由服务控制管理器(SCM)启动的服务
			SERVICE_ERROR_IGNORE,
			driverFilePath,//驱动文件放路径
			NULL,
			NULL,
			NULL,
			NULL,
			NULL);
		if (schService)
		{
			WriteLog(1,1,"install service:%s ok", chServiceName);
			CloseServiceHandle(schService); //创建完记得释放句柄
			bok = true;
		}
		else
		{
			WriteLog(1,1,"install driver %s failed:%d", chServiceName, GetLastError());
		}

		CloseServiceHandle(schSCManager);
	}

	return bok;
}

bool unloadDriver(LPCWSTR serviceName)//卸载
{
	bool bok = false;
	char chServiceName[260];
	SHTCharToAnsi(serviceName, chServiceName, 260);
	SC_HANDLE schSCManager;
	SC_HANDLE hs;
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager)
	{
		hs = OpenService(schSCManager, serviceName, SERVICE_ALL_ACCESS); //打开服务
		if (hs)
		{
			bool a = DeleteService(hs);   //删除服务
			if (!a)
			{
				WriteLog(1,1,"DeleteService:%s failed", chServiceName);
			}
			else
			{
				bok = true;
				WriteLog(1,1,"DeleteService:%s ok", chServiceName);
			}

			CloseServiceHandle(hs);//释放完后可完服务可从服务表中消失 释放前是
		}
		CloseServiceHandle(schSCManager);
	}
	return bok;
}

void startDriver(LPCWSTR serviceName)//启动
{
	SC_HANDLE schSCManager;
	SC_HANDLE hs;
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager)
	{
		hs = OpenService(schSCManager, serviceName, SERVICE_ALL_ACCESS); //打开服务
		char chserviceName[260];
		SHTCharToAnsi(serviceName, chserviceName, 260);
		if (hs)
		{
			SERVICE_STATUS serviceStatus;
			BOOL bqueryok = QueryServiceStatus(hs, &serviceStatus);
			if (bqueryok)
			{
				if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
				{
					if (StartService(hs, 0, 0))
					{
						WriteLog(1,1,"start service:%s ok", chserviceName);
					}
					else
					{
						WriteLog(1,1,"start service:%s failed:%d", chserviceName, GetLastError());
					}
				}
				else if (serviceStatus.dwCurrentState == SERVICE_RUNNING)
				{
					WriteLog(1,1,"service:%s is running", chserviceName);
				}
			}
			else
			{
				WriteLog(1,1,"QueryServiceStatus failed:%d, start service:%s failed", GetLastError(), chserviceName);
			}

			CloseServiceHandle(hs);
		}
		else
		{
			WriteLog(1,1,"service:%s have not install yet", chserviceName);
		}
		CloseServiceHandle(schSCManager);
	}
}

void stopDriver(LPCWSTR serviceName)//停止
{
	char chServiceName[260];
	SHTCharToAnsi(serviceName, chServiceName, 260);
	SC_HANDLE schSCManager;
	SC_HANDLE hs;
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager)
	{
		hs = OpenService(schSCManager, serviceName, SERVICE_ALL_ACCESS); //打开服务
		if (hs)
		{
			SERVICE_STATUS status;
			int num = 0;
			if (QueryServiceStatus(hs, &status))
			{
				//if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING)
				if (status.dwCurrentState == SERVICE_RUNNING)
				{
					ControlService(hs, SERVICE_CONTROL_STOP, &status);
					do
					{
						Sleep(50);
						num++;
						QueryServiceStatus(hs, &status);
					} while (status.dwCurrentState != SERVICE_STOPPED || num < 80);
					if (num > 80)
					{
						WriteLog(1,1,"stop service:%s failed:%d", chServiceName, GetLastError());
					}
					else
					{
						WriteLog(1,1,"stop service:%s service ok", chServiceName);
					}
				}
				else if (status.dwCurrentState == SERVICE_STOPPED)
				{
					WriteLog(1,1,"service:%s has been stoped", chServiceName);
				}
				else if (status.dwCurrentState == ERROR_SERVICE_DOES_NOT_EXIST)
				{
					WriteLog(1,1,"service:%s not exist", chServiceName);
				}
				else
				{
					WriteLog(1,1,"service:%s status:%d", chServiceName, status.dwCurrentState);
				}
			}

			CloseServiceHandle(hs);
		}
		CloseServiceHandle(schSCManager);
	}
}

