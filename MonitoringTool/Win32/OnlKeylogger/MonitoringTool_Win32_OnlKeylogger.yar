
rule MonitoringTool_Win32_OnlKeylogger{
	meta:
		description = "MonitoringTool:Win32/OnlKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {4b 65 79 6c 6f 67 67 65 72 4f 6e 6c 69 6e 65 2e 63 6f 6d 00 } //02 00 
		$a_00_1 = {4b 65 79 6c 6f 67 67 65 72 20 76 32 33 00 } //01 00 
		$a_00_2 = {4b 65 79 6c 6f 67 67 65 72 20 44 65 61 63 74 69 76 61 74 65 64 21 00 } //01 00 
		$a_00_3 = {44 65 61 63 74 69 76 61 74 65 64 20 4b 65 79 6c 6f 67 67 65 72 21 00 } //02 00 
		$a_00_4 = {5c 73 65 73 73 69 6f 6e 73 74 6f 72 65 2e 6a 73 } //02 00  \sessionstore.js
		$a_03_5 = {68 00 02 00 00 68 90 01 04 e8 90 01 04 6a 00 e8 90 01 04 6a 00 50 68 90 01 04 6a 0d e8 90 01 04 a3 90 01 04 6a 78 6a 03 68 bb bb aa 0a 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}