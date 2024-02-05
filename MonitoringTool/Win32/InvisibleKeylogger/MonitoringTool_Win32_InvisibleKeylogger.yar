
rule MonitoringTool_Win32_InvisibleKeylogger{
	meta:
		description = "MonitoringTool:Win32/InvisibleKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 49 6e 76 69 73 69 62 6c 65 20 4b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_01_1 = {6b 65 79 73 74 72 6f 6b 65 73 20 74 79 70 65 64 } //01 00 
		$a_01_2 = {44 69 73 61 62 6c 65 41 6e 74 69 73 70 79 } //00 00 
	condition:
		any of ($a_*)
 
}