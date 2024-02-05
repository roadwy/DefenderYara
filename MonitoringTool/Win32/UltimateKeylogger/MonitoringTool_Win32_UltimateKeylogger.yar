
rule MonitoringTool_Win32_UltimateKeylogger{
	meta:
		description = "MonitoringTool:Win32/UltimateKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {4b 4c 4b 6c 4d 6f 6e 2e 64 6c 6c 00 3f 41 64 64 4b 65 79 45 6e 74 72 79 40 90 02 ff 50 41 55 74 61 67 4b 65 79 52 65 73 75 6c 74 90 00 } //01 00 
		$a_00_1 = {4b 65 79 48 6f 6f 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_UltimateKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/UltimateKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 76 61 6c 75 61 74 69 6f 6e 20 63 6f 70 79 20 6f 66 20 55 6c 74 69 6d 61 74 65 20 4b 65 79 6c 6f 67 67 65 72 20 68 61 73 20 45 58 50 49 52 45 44 21 } //01 00 
		$a_01_1 = {63 6f 6e 74 61 63 74 20 73 75 70 70 6f 72 74 40 75 6c 74 69 6d 61 74 65 6b 65 79 6c 6f 67 67 65 72 2e 63 6f 6d } //01 00 
		$a_01_2 = {69 6e 63 6c 75 64 65 20 79 6f 75 72 20 4c 69 63 65 6e 73 65 20 4b 65 79 20 69 6e 20 75 6b 6c 2e 69 6e 69 20 66 69 6c 65 2e } //01 00 
		$a_01_3 = {70 61 73 73 77 6f 72 64 73 20 79 6f 75 20 74 79 70 65 64 20 64 6f 20 6e 6f 74 20 6d 75 74 63 68 2e } //01 00 
		$a_01_4 = {51 32 68 70 62 47 74 68 64 43 42 54 62 32 5a 30 64 32 46 79 5a 53 77 67 53 57 35 6a 4c 67 3d 3d } //01 00 
		$a_01_5 = {4b 52 79 4c 61 63 6b 20 4b 65 79 6c 6f 67 67 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_UltimateKeylogger_3{
	meta:
		description = "MonitoringTool:Win32/UltimateKeylogger,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 75 6c 6b 6c 66 65 6d 6f 6e 2e 64 6c 6c } //01 00 
		$a_01_1 = {4b 65 79 48 6f 6f 6b } //01 00 
		$a_01_2 = {5c 53 69 6c 65 6e 74 4b 65 79 } //01 00 
		$a_01_3 = {00 75 6b 66 72 65 65 2e 63 66 67 } //00 00 
	condition:
		any of ($a_*)
 
}