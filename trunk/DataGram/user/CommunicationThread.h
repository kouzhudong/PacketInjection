#pragma once

#include "pch.h"
#include "..\public\public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


#pragma pack(1)


/*
�˽ṹ����������޸ġ�
*/
typedef struct _MESSAGE {
    FILTER_MESSAGE_HEADER MessageHeader;//  Required structure header.

    NOTIFICATION Notification;//�Լ���������ݽṹ.

    //  Overlapped structure: this is not really part of the message
    //  However we embed it instead of using a separately allocated overlap structure
    OVERLAPPED Ovlp;
} MESSAGE, * PMESSAGE;


/*
�˽ṹ����������޸ġ�
*/
typedef struct _REPLY_MESSAGE {
    FILTER_REPLY_HEADER ReplyHeader;//  Required structure header.

    REPLY Reply;//�Լ���������ݽṹ.
} REPLY_MESSAGE, * PREPLY_MESSAGE;


#pragma pack()


//////////////////////////////////////////////////////////////////////////////////////////////////


void work();

