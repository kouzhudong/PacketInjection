目录说明：
1.DataGram
  实现了FWPS_INJECTION_TYPE_TRANSPORT，支持FWPM_LAYER_DATAGRAM_DATA_V4/6，
  可以添加FWPM_LAYER_ALE_AUTH_CONNECT_V4/6，FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/6，Windows-driver-samples\network\trans\inspect工程都是这样的。
  这个工程可能改自：Windows-driver-samples\network\trans\ddproxy。
  也可以考虑把Transport工程目录的内容移到这里。
  也可以考虑加入FWPS_INJECTION_TYPE_STREAM的功能，参考：Windows-driver-samples\network\trans\stmedit。
2.Transport
  实现了FWPS_INJECTION_TYPE_TRANSPORT，支持FWPM_LAYER_INBOUND_TRANSPORT_V4/6 + FWPM_LAYER_OUTBOUND_TRANSPORT_V4/6
3.IPPACKET
  实现了FWPS_INJECTION_TYPE_NETWORK，支持FWPM_LAYER_INBOUND_IPPACKET_V4/6 + FWPM_LAYER_OUTBOUND_IPPACKET_V4/6

有时间，单独写一个FWPS_INJECTION_TYPE_STREAM的测试工程。


18:31 2023/2/18


--------------------------------------------------------------------------------------------------


对于FWPS_INJECTION_TYPE_NETWORK及一下的的修改操作才需要计算校验和。
对于FWPS_INJECTION_TYPE_STREAM及FWPS_INJECTION_TYPE_TRANSPORT的修改不需要计算校验和，直接填写注入API的参数或者修改包的内容即可。

17:50 2023/2/19


--------------------------------------------------------------------------------------------------
