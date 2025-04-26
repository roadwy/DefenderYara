
rule MonitoringTool_Win32_WinMonitor{
	meta:
		description = "MonitoringTool:Win32/WinMonitor,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 53 70 79 } //1 AntSpy
		$a_01_1 = {66 52 45 43 57 43 61 6d } //1 fRECWCam
		$a_00_2 = {54 00 53 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5c 00 } //1 TS Security\
		$a_00_3 = {64 00 5f 00 48 00 69 00 64 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 46 00 69 00 6c 00 65 00 73 00 } //1 d_HideSystemFiles
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}