
rule Backdoor_Win32_Agent_FQ{
	meta:
		description = "Backdoor:Win32/Agent.FQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b e8 ff d3 33 d2 f7 f5 83 ee 01 8a 92 ?? ?? ?? ?? 88 14 37 75 } //1
		$a_03_1 = {6a 00 57 56 6a 05 e8 ?? ?? 00 00 3d 04 00 00 c0 74 ?? 85 c0 7d } //1
		$a_02_2 = {53 65 74 4b 65 72 6e 65 6c 4f 62 6a 65 63 74 53 65 63 75 72 69 74 79 00 ?? ?? 4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}