
rule MonitoringTool_Win32_GhostXP{
	meta:
		description = "MonitoringTool:Win32/GhostXP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {47 68 6f 73 74 58 50 00 90 02 10 53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 90 02 10 52 65 63 79 63 6c 65 72 90 02 10 5c 77 33 77 69 6e 78 70 2e 69 6e 69 90 02 10 5c 77 34 77 69 6e 2e 69 6e 69 90 00 } //01 00 
		$a_02_1 = {44 61 74 61 44 65 49 6e 73 74 00 90 02 10 44 61 74 61 48 69 73 74 52 6f 7a 00 90 02 10 44 61 74 61 48 69 73 74 5a 61 6b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}