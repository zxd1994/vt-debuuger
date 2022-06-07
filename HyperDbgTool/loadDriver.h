#pragma once

#include <Windows.h>
bool installDriver(LPCWSTR serviceName, LPCWSTR displayName, LPCWSTR driverFilePath);
void startDriver(LPCWSTR serviceName);//Æô¶¯Çý¶¯
void stopDriver(LPCWSTR serviceName);//Í£Ö¹Çý¶¯
bool unloadDriver(LPCWSTR serviceName);//Ð¶ÔØÇý¶¯