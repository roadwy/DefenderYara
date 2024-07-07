
rule MonitoringTool_Win32_FreeKeylogger{
	meta:
		description = "MonitoringTool:Win32/FreeKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 53 68 6f 77 20 46 72 65 65 20 4b 65 79 20 4c 6f 67 67 65 72 } //1 &Show Free Key Logger
		$a_01_1 = {4d 6f 6e 69 74 6f 72 69 6e 67 20 52 65 73 75 6d 65 64 } //1 Monitoring Resumed
		$a_01_2 = {54 43 6c 69 70 62 6f 61 72 64 4d 6f 6e 69 74 6f 72 53 } //1 TClipboardMonitorS
		$a_01_3 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 6c 65 61 72 20 6c 6f 67 73 } //1 Do you want to clear logs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}