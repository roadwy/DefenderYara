
rule Backdoor_Win32_Agent_FQ{
	meta:
		description = "Backdoor:Win32/Agent.FQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b e8 ff d3 33 d2 f7 f5 83 ee 01 8a 92 90 01 04 88 14 37 75 90 00 } //01 00 
		$a_03_1 = {6a 00 57 56 6a 05 e8 90 01 02 00 00 3d 04 00 00 c0 74 90 01 01 85 c0 7d 90 00 } //01 00 
		$a_02_2 = {53 65 74 4b 65 72 6e 65 6c 4f 62 6a 65 63 74 53 65 63 75 72 69 74 79 00 90 01 02 4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}