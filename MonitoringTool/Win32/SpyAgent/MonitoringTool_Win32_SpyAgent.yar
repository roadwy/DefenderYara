
rule MonitoringTool_Win32_SpyAgent{
	meta:
		description = "MonitoringTool:Win32/SpyAgent,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 70 79 41 67 65 6e 74 5f 48 57 4e 44 33 32 } //01 00 
		$a_01_1 = {25 73 5c 73 61 6f 70 74 73 2e 64 61 74 } //01 00 
		$a_01_2 = {53 70 79 74 65 63 68 20 53 70 79 41 67 65 6e 74 } //01 00 
		$a_01_3 = {43 6c 69 65 6e 74 20 68 6f 6f 6b 20 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_SpyAgent_2{
	meta:
		description = "MonitoringTool:Win32/SpyAgent,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 77 69 6e 64 6f 77 73 5c 6c 73 61 73 73 2e 65 78 65 } //02 00 
		$a_01_1 = {53 50 59 41 47 45 4e 54 40 } //01 00 
		$a_01_2 = {3d 3e 4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 } //01 00 
		$a_01_3 = {56 69 63 74 69 6d 20 69 73 20 4f 6e 6c 69 6e 65 } //01 00 
		$a_01_4 = {20 55 52 4c 20 48 49 53 54 4f 52 59 20 3d } //01 00 
		$a_01_5 = {4c 6f 67 20 53 74 61 72 74 20 20 } //00 00 
	condition:
		any of ($a_*)
 
}