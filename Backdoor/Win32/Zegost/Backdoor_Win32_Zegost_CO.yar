
rule Backdoor_Win32_Zegost_CO{
	meta:
		description = "Backdoor:Win32/Zegost.CO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 56 57 68 dc dd 1a 33 e8 } //1
		$a_01_1 = {8b f0 c1 ee 1b c1 e0 05 0b f0 0f b6 c1 8a 4a 01 03 c6 42 84 c9 75 e9 } //1
		$a_03_2 = {5c 5c 73 65 c7 85 ?? ?? ?? ?? 72 76 2e 74 c7 85 ?? ?? ?? ?? 78 74 00 78 89 4d a8 c7 45 ?? 69 63 65 73 c7 45 ?? 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}