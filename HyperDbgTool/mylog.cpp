#include  "pch.h"
#include <Windows.h>
#include <iostream>

char g_szLogFileName[MAX_PATH] = { 0 };
#define MaxLogLen 1024*10
#define MaxLogFileLen 1024*1024

void GetRunPathA(char* lpPath)
{
	if (lpPath == NULL) return;

	GetModuleFileNameA(NULL, lpPath, MAX_PATH);

	for (int i = strlen(lpPath) - 1; i > 0; i--)
	{
		if (lpPath[i] == '\\')
		{
			lpPath[i] = '\0';
			break;
		}
	}
}

void GetLogFileName()
{
	//取临时日志文件的名字
	if (strlen(g_szLogFileName) <= 0)
	{
		WCHAR wcsTemp[MAX_PATH] = { 0 };
		char csTemp[MAX_PATH] = { 0 };
		GetRunPathA(csTemp);
		strcat_s(csTemp, "\\HyperDbgTool.log");
		strcpy_s(g_szLogFileName, csTemp);
	}
}

void WriteLog(bool bOutput, bool bWantProcessName, const char* fmt, ...)//其实就是WriteLogFile
{
	if (!bOutput) return;

	GetLogFileName();

	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFileA(g_szLogFileName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return;
	}
	va_list args;
	char temp[MaxLogLen] = { 0 };
	DWORD dwFileLen = GetFileSize(hFile, NULL);
	if (dwFileLen > MaxLogFileLen)//避免文件太大造成假死
	{
		SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
		SetEndOfFile(hFile);
	}
	else
	{
		SetFilePointer(hFile, 0, NULL, FILE_END);
	}

	SYSTEMTIME time;
	GetLocalTime(&time);
	sprintf_s(temp, "%d-%d-%d %d:%d:%d ", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);

	DWORD dw;
	if (bWantProcessName)
	{
		char modname[MAX_PATH];
		GetModuleFileNameA(NULL, modname, sizeof(modname));
		wsprintfA(temp + strlen(temp), "%s:", modname);
	}
	va_start(args, fmt);
	vsprintf(temp + strlen(temp), fmt, args);
	va_end(args);

	strcat_s(temp, "\r\n");
	WriteFile(hFile, temp, strlen(temp), &dw, NULL);

	CloseHandle(hFile);
}