#pragma once

//常量
#define MAX_PATH          260
/*==============================================================================*/
/*                                自定义结构                                    */
/*==============================================================================*/

 typedef struct _LIST_LINK  //自定义单向链表节点
 {
	 PVOID DataPtr;
	 PVOID Data;//附加数据
	 struct _LIST_LINK* next;
 } LIST_LINK, * PLIST_LINK;
 typedef struct _LIST_HEAD  //自定义单向链表头
 {
	 struct _LIST_LINK ListHead;
	 ULONG_PTR m_Size;

 } LIST_HEAD, * PLIST_HEAD;
 typedef struct _LIST_ARRAY//自定义动态数组
 {
	 PVOID DataPtr;//数组指针
	 ULONG_PTR m_CurrentNumber;//当前元素个数
	 ULONG_PTR m_Size;//数组容量个数

 }LIST_ARRAY, * PLIST_ARRAY;


 typedef struct _TZM {
	 UCHAR	Tzm;
	 int		Offset;
 }TZM, * PTZM;


 typedef struct _ADDRESS_NAME  //R3传入符号结构
 {
	 IN	char  Name[MAX_PATH];
	 PVOID Address;

 }ADDRESS_NAME, * PADDRESS_NAME;