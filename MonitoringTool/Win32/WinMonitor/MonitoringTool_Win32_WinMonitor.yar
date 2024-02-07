
rule MonitoringTool_Win32_WinMonitor{
	meta:
		description = "MonitoringTool:Win32/WinMonitor,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6e 74 53 70 79 } //01 00  AntSpy
		$a_01_1 = {66 52 45 43 57 43 61 6d } //01 00  fRECWCam
		$a_00_2 = {54 00 53 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5c 00 } //01 00  TS Security\
		$a_00_3 = {64 00 5f 00 48 00 69 00 64 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 46 00 69 00 6c 00 65 00 73 00 } //00 00  d_HideSystemFiles
		$a_00_4 = {5d 04 00 } //00 2c 
	condition:
		any of ($a_*)
 
}