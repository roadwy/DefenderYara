
rule MonitoringTool_AndroidOS_AndSpy_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/AndSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {48 65 61 72 74 62 65 61 74 44 69 73 70 61 74 63 68 65 72 } //1 HeartbeatDispatcher
		$a_00_1 = {64 65 6c 65 74 65 42 72 6f 77 73 65 72 48 69 73 74 6f 72 79 } //1 deleteBrowserHistory
		$a_00_2 = {73 70 79 73 65 74 75 70 2e 63 6f 6d } //1 spysetup.com
		$a_00_3 = {73 65 72 76 65 72 2e 66 72 65 65 61 6e 64 72 6f 69 64 73 70 79 2e 63 6f 6d 2f 69 6e 64 65 78 2e 70 68 70 } //1 server.freeandroidspy.com/index.php
		$a_00_4 = {63 6c 69 65 6e 74 5f 6c 6f 67 } //1 client_log
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}