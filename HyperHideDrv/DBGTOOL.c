#include "ntddk.h"
#include "dbgtool.h"


p_save_handlentry createlist(){
	ULONG i;

	p_save_handlentry phead = (p_save_handlentry)ExAllocatePool(NonPagedPool, sizeof(_save_handlentry));
	p_save_handlentry ptail = phead;
	ptail->next = NULL;
	p_save_handlentry pnew = (p_save_handlentry)ExAllocatePool(NonPagedPool, sizeof(_save_handlentry));

	pnew->dbgProcessId = 0;
	pnew->dbgProcessStruct = 0;
	pnew->head = NULL;
	ptail->next = pnew;
	pnew->next = NULL;
	ptail->head = NULL;
	


	return phead;

}
// 插入链表 
p_save_handlentry insertlist(HANDLE dbgProcessId,
PEPROCESS dbgProcessStruct ,p_save_handlentry phead){


	

	p_save_handlentry p = phead->next;

	while (p != NULL)
	{
		if (p->next == NULL){
			break;
		}
		p = p->next;
	}

	p_save_handlentry pnew = (p_save_handlentry)ExAllocatePool(NonPagedPool, sizeof(_save_handlentry));
	
	pnew->dbgProcessId = dbgProcessId;
	pnew->dbgProcessStruct = dbgProcessStruct;




	p->next = pnew;
	pnew->next = NULL;
	pnew->head = p;

	
	return pnew;
}
p_save_handlentry querylist(p_save_handlentry phead, HANDLE dbgProcessId, PEPROCESS dbgProcessStruct){

	
	p_save_handlentry p = phead->next;
	while (p != NULL)
	{
		if (dbgProcessId!=NULL
			)
		{
			if (p->dbgProcessId == dbgProcessId){
				
				return p;
			}
		}
		
		if (dbgProcessStruct!=NULL
			)
		{
			if (p->dbgProcessStruct == dbgProcessStruct){
			
				return p;
			}

		}
		
		p = p->next;
	}


	return NULL;
}
//删除节点
void deletelist(p_save_handlentry pclid){
	p_save_handlentry p, pp;



	if (pclid->head != NULL){//头部
		p = pclid->head;
		pp = pclid->next;


		if (pp == NULL){//最后节点
			p->next = NULL;
			ExFreePool(pclid);
			
			return;
		}


		p->next = pp;//不是最后节点
		pp->head = p;
		ExFreePool(pclid);

		return;
	}
	

}
