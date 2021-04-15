#pragma once

#include "DriverEntry.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
����UserProcess��һ��˵����
��ֹ���̱��Ƿ��������ӽ��̱��Ƿ�������FltCloseClientPort�����ڼ�������ֵ������⡣
����취�ǣ�
1.���̻ص����������̵��˳����Ҷ����ֵ����ԭ�Ӳ�����
2.ExInitializeRundownProtectionϵ�к�����û�ù�����ЩҲ���ܽ������Ϊ���̵������Ա��ַ��δ֪�ģ���Ϊ���̶���δ������
*/
typedef struct _DATA {
    PDRIVER_OBJECT DriverObject;//  The object that identifies this driver.
    PFLT_FILTER Filter;//  The filter handle that results from a call to FltRegisterFilter.
    PFLT_PORT ServerPort;//  Listens for incoming connections
    PEPROCESS UserProcess;//  User process that connected to the port 
    PFLT_PORT ClientPort;//  Client port for a connection to user-mode
} DATA, * PDATA;


//////////////////////////////////////////////////////////////////////////////////////////////////


extern DATA g_Data;

NTSTATUS CreateCommunicationPort(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
