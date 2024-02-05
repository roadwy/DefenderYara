
rule MonitoringTool_Win32_AaronKeylogger{
	meta:
		description = "MonitoringTool:Win32/AaronKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 61 72 6f 6e 20 4b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 72 65 6d 6f 74 65 2d 6b 65 79 6c 6f 67 67 65 72 2e 6e 65 74 } //01 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 72 65 66 75 64 2e 6d 65 2f 73 63 61 6e 2e 70 68 70 } //01 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 65 76 65 72 62 6f 74 2e 70 6c 2f 63 73 2f 72 65 67 2e 70 68 70 3f 69 64 3d } //00 00 
	condition:
		any of ($a_*)
 
}