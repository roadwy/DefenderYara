
rule MonitoringTool_Win32_AwardKeylogger{
	meta:
		description = "MonitoringTool:Win32/AwardKeylogger,SIGNATURE_TYPE_PEHSTR,0e 00 0b 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 41 70 70 } //05 00 
		$a_01_1 = {73 74 65 61 6c 74 68 } //01 00 
		$a_01_2 = {73 6d 74 70 20 73 65 72 76 65 72 } //01 00 
		$a_01_3 = {2f 53 69 6c 65 6e 74 20 2f 4e 6f 49 63 6f 6e } //01 00 
		$a_01_4 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00 
		$a_01_5 = {4d 6f 6e 69 74 6f 72 69 6e 67 20 65 6e 67 69 6e 65 } //00 00 
	condition:
		any of ($a_*)
 
}