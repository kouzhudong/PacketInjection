#pragma once

#include "pch.h"
#include "..\public\public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


#pragma pack(1)


/*
此结构不建议随便修改。
*/
typedef struct _MESSAGE {
    FILTER_MESSAGE_HEADER MessageHeader;//  Required structure header.

    NOTIFICATION Notification;//自己定义的数据结构.

    //  Overlapped structure: this is not really part of the message
    //  However we embed it instead of using a separately allocated overlap structure
    OVERLAPPED Ovlp;
} MESSAGE, * PMESSAGE;


/*
此结构不建议随便修改。
*/
typedef struct _REPLY_MESSAGE {
    FILTER_REPLY_HEADER ReplyHeader;//  Required structure header.

    REPLY Reply;//自己定义的数据结构.
} REPLY_MESSAGE, * PREPLY_MESSAGE;


#pragma pack()


//////////////////////////////////////////////////////////////////////////////////////////////////


void work();

