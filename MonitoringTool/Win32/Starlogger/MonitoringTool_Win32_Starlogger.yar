
rule MonitoringTool_Win32_Starlogger{
	meta:
		description = "MonitoringTool:Win32/Starlogger,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 4d 61 6e 61 67 65 6d 65 6e 74 5c 41 52 50 43 61 63 68 65 5c 53 74 61 72 4c 6f 67 67 65 72 5f 69 73 31 } //01 00 
		$a_01_1 = {52 75 6e 20 53 74 61 72 4c 6f 67 67 65 72 } //01 00 
		$a_01_2 = {5b 6c 65 66 74 20 77 69 6e 64 6f 77 73 5d } //01 00 
		$a_01_3 = {44 65 73 6b 74 6f 70 20 77 69 6c 6c 20 62 65 20 63 61 70 74 75 72 65 64 20 72 65 67 75 6c 61 72 6c 79 2e } //00 00 
	condition:
		any of ($a_*)
 
}