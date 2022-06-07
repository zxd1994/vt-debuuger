
typedef struct _save_handlentry{
	struct _save_handlentry*head;
	HANDLE dbgProcessId;
	PEPROCESS dbgProcessStruct;

	struct _save_handlentry*next;

}_save_handlentry, *p_save_handlentry;

p_save_handlentry createlist();
p_save_handlentry insertlist(HANDLE dbgProcessId,
	PEPROCESS dbgProcessStruct, p_save_handlentry phead);
p_save_handlentry querylist(p_save_handlentry phead, HANDLE dbgProcessId, PEPROCESS dbgProcessStruct);
void deletelist(p_save_handlentry pclid);
