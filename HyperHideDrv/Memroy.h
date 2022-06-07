#pragma once
#include "Header.h"

	enum  TzmMode
	{
		Normal,
		Call,
		Mov,
		Lea
	};

	 BOOLEAN WriteKernelMemory
	(
		PVOID pDestination,
		PVOID pSourceAddress,
		SIZE_T SizeOfCopy);
	 BOOLEAN ReadKernelMemory
	(
		PVOID pDestination,
		PVOID pSourceAddress,
		SIZE_T SizeOfCopy);


	 KIRQL WPOFFx64();
	 void  WPONx64(KIRQL irql);
	/************************************************************************
	*   Name : FindMemory
	* Param  : SearAddress 起始地址
	* Param  : SearLenth   搜索长度
	* Param  : Mode        搜索模式 CMemroyNormal//CMemroyCall//CMemroyMov
	* Param  : Tzm[5]      特征码   TZM a[5] = { {0, 0}, { 0,0}, { 0,0 },  {0,0} , { 0,0} };/(特征码,偏移) e8偏移=0
	*     Ret: PVOID
	*  内存搜索
	************************************************************************/
	 PVOID FindMemory(
		PVOID   SearAddress,
		ULONG   SearLenth,
		TzmMode Mode,
		TZM    Tzm[5]);

	 PVOID FindMemoryFromReadAndWriteSection(
		 PVOID ModuleBass,
		 TzmMode Mode, 
		 TZM Tzm[5]);


	


