
rule MonitoringTool_Win32_SpyBuddy{
	meta:
		description = "MonitoringTool:Win32/SpyBuddy,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 70 79 42 75 64 64 79 20 53 65 73 73 69 6f 6e 20 52 65 70 6f 72 74 } //01 00 
		$a_01_1 = {62 79 20 53 70 79 42 75 64 64 79 21 } //01 00 
		$a_01_2 = {42 65 20 4d 6f 6e 69 74 6f 72 65 64 } //01 00 
		$a_01_3 = {6b 65 79 77 6f 72 64 20 6f 72 20 70 68 72 61 73 65 } //01 00 
		$a_01_4 = {5f 68 6f 6f 6b 5d } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_SpyBuddy_2{
	meta:
		description = "MonitoringTool:Win32/SpyBuddy,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 61 6b 62 68 2e 64 6c 6c 00 43 72 65 61 74 65 00 46 72 65 65 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_2 = {25 73 20 25 30 2e 32 64 2f 25 30 2e 32 64 2f 25 30 2e 32 64 20 40 20 25 30 2e 32 64 3a 25 30 2e 32 64 3a 25 30 2e 32 64 } //01 00 
		$a_01_3 = {45 41 4b 42 46 69 6c 65 4d 61 70 70 69 6e 67 } //01 00 
		$a_01_4 = {25 73 25 64 63 2e 64 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_SpyBuddy_3{
	meta:
		description = "MonitoringTool:Win32/SpyBuddy,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 73 68 65 72 3d 45 78 70 6c 6f 72 65 41 6e 79 77 68 65 72 65 20 53 6f 66 74 77 61 72 65 2c } //01 00 
		$a_01_1 = {54 69 74 6c 65 3d 53 70 79 42 75 64 64 79 } //01 00 
		$a_01_2 = {2f 73 70 79 62 75 64 64 79 2d 73 65 74 75 70 2d } //01 00 
		$a_01_3 = {25 44 45 53 4b 54 4f 50 25 5c 44 6f 77 6e 6c 6f 61 64 73 } //01 00 
		$a_01_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //00 00 
	condition:
		any of ($a_*)
 
}