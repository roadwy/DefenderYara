
rule MonitoringTool_Win32_PCAgent{
	meta:
		description = "MonitoringTool:Win32/PCAgent,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 6f 6e 50 77 57 61 74 63 68 } //01 00 
		$a_01_1 = {50 43 41 5f 53 45 54 54 49 4e 47 53 } //01 00 
		$a_01_2 = {48 6f 6f 6b 57 61 74 63 68 2e 47 65 74 4d 6f 75 73 65 4d 65 73 73 61 67 65 } //01 00 
		$a_01_3 = {20 50 43 41 20 4d 61 69 6c 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_PCAgent_2{
	meta:
		description = "MonitoringTool:Win32/PCAgent,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 43 20 4d 6f 6e 69 74 6f 72 69 6e 67 20 53 6f 66 74 77 61 72 65 } //01 00 
		$a_01_1 = {62 6c 75 65 2d 73 65 72 69 65 73 2e 64 65 } //01 00 
		$a_01_2 = {4f 70 65 6e 20 61 6e 64 20 76 69 65 77 20 74 68 65 20 6c 6f 67 2d 66 69 6c 65 73 } //01 00 
		$a_01_3 = {50 63 61 43 68 65 63 6b 56 65 72 73 69 6f 6e 43 68 6b 56 41 76 61 69 6c 61 62 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}