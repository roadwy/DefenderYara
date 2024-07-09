
rule Virus_Win32_Sirefef_gen_A{
	meta:
		description = "Virus:Win32/Sirefef.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 53 63 55 6e } //1 hScUn
		$a_03_1 = {8b 75 0c 8b 46 04 57 6a 5c 50 ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? [0-04] 85 c0 75 0a } //1
		$a_01_2 = {56 8a 0a 6b c0 21 0f be f1 33 c6 42 84 c9 75 f1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Virus_Win32_Sirefef_gen_A_2{
	meta:
		description = "Virus:Win32/Sirefef.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 53 63 55 6e } //1 hScUn
		$a_03_1 = {8b 75 0c 8b 46 04 57 6a 5c 50 ff 15 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? [0-04] 85 c0 75 0a } //1
		$a_01_2 = {56 8a 0a 6b c0 21 0f be f1 33 c6 42 84 c9 75 f1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}