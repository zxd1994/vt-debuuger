#pragma once
#include "Header.h"

//PETHREAD PsGetNextProcessThread(
//	IN PEPROCESS Process,
//	IN PETHREAD Thread
//);

NTSTATUS  NtOpenDirectoryObject(
	__out PHANDLE DirectoryHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes
);

