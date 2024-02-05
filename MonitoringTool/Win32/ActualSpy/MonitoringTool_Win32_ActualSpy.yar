
rule MonitoringTool_Win32_ActualSpy{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 68 70 72 6f 67 2e 64 6c 6c 00 48 69 64 65 90 02 01 50 72 6f 63 65 73 73 00 53 68 6f 77 50 72 6f 63 65 73 73 90 00 } //01 00 
		$a_00_1 = {6e 74 68 69 64 65 66 69 6c 65 6d 61 70 70 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_ActualSpy_2{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 4b 65 79 62 6f 61 72 64 48 6f 6f 6b } //01 00 
		$a_00_1 = {75 23 f7 c3 00 00 00 80 75 1b 83 ff 10 75 16 56 6a 01 68 13 2b 00 00 } //01 00 
		$a_00_2 = {61 70 70 68 6f 6f 6b } //01 00 
		$a_00_3 = {6d 6f 75 73 65 68 6f 6f 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_ActualSpy_3{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6b 64 6c 6c 2e 64 6c 6c 00 52 65 6d 6f 76 65 41 70 70 48 6f 6f 6b } //01 00 
		$a_01_1 = {66 72 6f 6d 20 68 6f 6f 6b 64 6c 6c 2e 64 6c 6c } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 4c 6f 63 61 6c 65 73 } //01 00 
		$a_01_3 = {53 65 74 4b 65 79 62 6f 61 72 64 48 6f 6f 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_ActualSpy_4{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 41 4b 50 72 6f 67 72 61 6d 5c 4b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_01_1 = {73 70 79 5f 6f 6e 6c 79 5f 63 68 61 72 } //01 00 
		$a_01_2 = {74 6f 20 73 68 6f 77 20 41 63 74 75 61 6c 20 4b 65 79 6c 6f 67 67 65 72 } //01 00 
		$a_01_3 = {41 63 74 75 61 6c 20 4b 65 79 6c 6f 67 67 65 72 5f 69 73 } //01 00 
		$a_01_4 = {41 63 74 75 61 6c 20 53 70 79 20 2d 20 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_ActualSpy_5{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {4b 65 79 4d 4d 46 } //01 00 
		$a_00_1 = {41 70 70 48 6f 6f 6b } //01 00 
		$a_00_2 = {44 65 73 74 72 6f 79 48 6f 6f 6b } //01 00 
		$a_00_3 = {4b 65 79 62 6f 61 72 64 48 6f 6f 6b } //01 00 
		$a_00_4 = {4d 6f 75 73 65 48 6f 6f 6b } //01 00 
		$a_00_5 = {53 68 69 66 74 43 61 70 73 48 6f 6f 6b } //01 00 
		$a_00_6 = {57 69 6e 64 6f 77 48 6f 6f 6b } //01 00 
		$a_00_7 = {6e 65 77 6e 65 77 } //03 00 
		$a_01_8 = {74 2f 6a 38 6a 00 6a 00 68 1f 00 0f 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule MonitoringTool_Win32_ActualSpy_6{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 74 72 6c 2b 41 6c 74 2b 53 68 69 66 74 2b 46 38 } //02 00 
		$a_01_1 = {61 63 74 75 61 6c 73 70 79 72 65 70 40 67 6d 61 69 6c 2e 63 6f 6d } //02 00 
		$a_01_2 = {73 75 70 70 6f 72 74 40 61 63 74 75 61 6c 73 70 79 } //02 00 
		$a_01_3 = {66 74 70 2e 61 63 74 75 61 6c 73 70 79 2e 63 6f 6d } //02 00 
		$a_01_4 = {44 69 72 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_01_5 = {41 63 74 75 61 6c 20 53 70 79 } //01 00 
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 41 4b 4d 6f 6e 69 74 6f 72 5c } //01 00 
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 41 53 4d 6f 6e 5c } //00 00 
	condition:
		any of ($a_*)
 
}