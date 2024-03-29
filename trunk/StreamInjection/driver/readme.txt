要使KdPrintEx((DPFLTR_IHVNETWORK_ID,...生效的两种种办法:
1.先加nt的载符号文件，
  然后运行windbg命令：ed nt!Kd_IHVNETWORK_Mask f 
  这个办法立即生效，
  同时也是关闭的办法, 只需再次设置这个值为0即可。
2.另一种办法使修改注册表.
  如果用reg文件，内容如下：
  Windows Registry Editor Version 5.00

  [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter]
  "IHVNETWORK"=dword:0000000f
  但是需要重启.


--------------------------------------------------------------------------------------------------


WPP要在windbg中显示,需要设置traceview.exe.


--------------------------------------------------------------------------------------------------


MmMapLockedPagesSpecifyCache
可以用于映射内核内存到应用层，但是应用层的进程何在？尽管MDL有进程对象。
切换（KeStackAttachProcess ）到进程上下文看看。
The routine returns a user address that is valid in the context of the process in which the driver is running. 
For example, if a 64-bit driver is running in the context of a 32-bit application, the buffer is mapped to an address in the 32-bit address range of the application.
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmaplockedpagesspecifycache


--------------------------------------------------------------------------------------------------


本驱动会概率性的引起intel的网卡驱动蓝屏（VMWARE虚拟机环境）。


Divert工程的inbound_network会放弃处理：FWP_CONDITION_FLAG_IS_FRAGMENT和FWP_CONDITION_FLAG_IS_LOOPBACK。


--------------------------------------------------------------------------------------------------


Filtering condition flags
https://docs.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags
https://docs.microsoft.com/en-us/windows/win32/fwp/filtering-condition-flags-
哪些layers有哪些flags


--------------------------------------------------------------------------------------------------


TCP Packet Flows
https://docs.microsoft.com/en-us/windows/win32/fwp/tcp-packet-flows
TCP三次握手走哪些layers


UDP Packet Flows
https://docs.microsoft.com/en-us/windows/win32/fwp/udp-packet-flows
UDP走哪些layers


Filtering Layer Identifiers
https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
各个Layer的说明。


--------------------------------------------------------------------------------------------------


防止进程退出的思路是：
1.增加进程的引用计数，如：ObReferenceObject， ObReferenceObjectByPointer, OpenObjectXXX等，有待实验，应该可以。
2.是ExInitializeRundownProtection机制，这个不建议，因为这个成员在进程对象中。
3.进程回调的退出时原子操作。


--------------------------------------------------------------------------------------------------


关于FwpsStreamInjectAsync的用法：
可参考：
Windows-driver-samples\network\trans\stmedit
Windows-driver-samples\network\trans\WFPSampler


\Windows-driver-samples\network\trans\WFPSampler\sys\ClassifyFunctions_BasicStreamInjectionCallouts.cpp的PerformBasicStreamInjection函数。
\Windows-driver-samples\network\trans\WFPSampler\sys\ClassifyFunctions_FastStreamInjectionCallouts.cpp 的ClassifyFastStreamInjection函数。

还有函数
FwpsDiscardClonedStreamData。
FwpsAllocateNetBufferAndNetBufferList
FwpsFreeNetBufferList


--------------------------------------------------------------------------------------------------


谨记：DPC上禁止用汉字（包括中文字符）。
所以，这里任何的打印去掉汉字（包括中文字符）。


--------------------------------------------------------------------------------------------------
