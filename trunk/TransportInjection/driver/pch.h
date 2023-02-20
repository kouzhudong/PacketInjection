/*
�ļ�����ȡ��VS2017�Ŀ���̨ʾ�����̵�ͷ�ļ�.

����:Ԥ����ͷ,����û��������ǿ�Ƶ�һ����������ļ�.

ע��:
1.����ļ�ֻ����ϵͳ��ͷ�ļ���һЩ����������.
2.����ļ�ֻ����һЩ����������.
3.Ҳ����˵���ͷ�ļ�ֻ׼��������ļ�,��׼�ٰ������ϵͳ�ļ�.

���ļ���Ҫ���ڽ��:
1.ϵͳ�ļ��������µı����������.
2.ͳһ�滮�ļ��İ�����ϵ.
*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif


    ///////////////////////////////////////////////////////////////////////////////////////////////


#if (NTDDI_VERSION >= NTDDI_VISTA)
#define NDIS60 1
#define NDIS_SUPPORT_NDIS6 1
#endif 

#define POOL_NX_OPTIN 1

#pragma warning(disable:4200) // ʹ���˷Ǳ�׼��չ : �ṹ/�����е����С����
#pragma warning(disable:4201) // unnamed struct/union
#pragma warning(disable:4214) // ʹ���˷Ǳ�׼��չ: ���������λ������
#pragma warning(disable:4127) // �������ʽ�ǳ���
#pragma warning(disable:4057) // ����΢��ͬ�Ļ����ͼ��Ѱַ�ϲ�ͬ
#pragma warning(disable:4152) // �Ǳ�׼��չ�����ʽ�еĺ���/����ָ��ת��
#pragma warning(disable:28172) //The function 'XXX' has PAGED_CODE or PAGED_CODE_LOCKED but is not declared to be in a paged segment. ԭ��1.������IRQL������2.�����ڵĺ����Ĳ����þֲ���������Ҫ����������ǷǷ�ҳ�ڴ档

#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include <windef.h> //Ӧ�÷���ntddk.h�ĺ���.
#include <in6addr.h>
#include <ip2string.h>

#define INITGUID
#include <guiddef.h>

#include <ndis.h>
#include <initguid.h> //��̬����UUID�õģ�����error LNK2001��
#include <Ntstrsafe.h>
#include <ipmib.h>
#include <netpnp.h>
#include <ntintsafe.h>
#include <fltkernel.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <initguid.h>

/*
WDK7600.16385.1���ں�ͷ�ļ�û��u_short�Ķ���,�û����ͷ�ļ���u_short�Ķ���.
SOCKADDR�ṹ���õ�u_short.
SOCKADDR��ws2def.h�ж���.
ws2def.h������ֱ�Ӱ���.
netioapi.h����ws2def.h���ļ�.
������WDK7600.16385.1��,���������Ӧ�ò��ͷ�ļ�,Ӧ���ڰ���netioapi.h֮ǰ,����u_short�Ķ���.
����,ÿ������(������Ӱ���)ws2def.h��c/cpp�ļ�������һ��ѵĴ���.
*/
    typedef unsigned short  u_short;
#include <netioapi.h>
    //#include <ws2def.h>
#include <ws2ipdef.h>

#include <mstcpip.h>
#include <wmilib.h>
#include <wmistr.h>

#define NTSTRSAFE_LIB

#include <tdi.h>
#include <tdiinfo.h>
#include <tdikrnl.h>
#include <tdistat.h>
//#include <fwpmk.h>
//#include <wsk.h>
#include <ntimage.h>

#include <fwpsk.h>  //NDIS61

#include <dontuse.h>
#include <suppress.h>
#include <aux_klib.h>


#define TAG 'tset' //test


#ifdef __cplusplus
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define __FILENAMEW__ (wcsrchr(_CRT_WIDE(__FILE__), L'\\') ? wcsrchr(_CRT_WIDE(__FILE__), L'\\') + 1 : _CRT_WIDE(__FILE__))

/*
��֧�ֵ��ַ�Ҳ֧�ֿ��ַ���
ע�⣺
1.�����������ǵ��ַ�������Ϊ�գ�����ҪΪNULL��������ʡ�ԡ�
2.������DPC�ϲ�Ҫ��ӡ���ַ���
3.
*/

//���֧��3����������
#define Print(ComponentId, Level, Format, ...) \
{DbgPrintEx(ComponentId, Level, "FILE:%s, LINE:%d, "##Format".\r\n", __FILENAME__, __LINE__, __VA_ARGS__);}

//�������4��������
#define PrintEx(ComponentId, Level, Format, ...) \
{KdPrintEx((ComponentId, Level, "FILE:%s, LINE:%d, "##Format".\r\n", __FILENAME__, __LINE__, __VA_ARGS__));}


//////////////////////////////////////////////////////////////////////////////////////////////////
