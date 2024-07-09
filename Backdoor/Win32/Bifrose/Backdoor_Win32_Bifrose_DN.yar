
rule Backdoor_Win32_Bifrose_DN{
	meta:
		description = "Backdoor:Win32/Bifrose.DN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 a3 ?? ?? 40 00 8b 0d ?? ?? 40 00 3b 0d ?? ?? 40 00 7e 0c 8b 15 ?? ?? 40 00 89 15 ?? ?? 40 00 } //1
		$a_01_1 = {6b d2 09 03 c2 33 d2 be e8 03 00 00 f7 f6 2b ca 89 4d fc 83 7d f8 00 } //1
		$a_03_2 = {68 94 02 00 00 8b 0d ?? ?? 40 00 51 68 94 02 00 00 8b 95 ?? ?? ?? ?? 52 8b 45 ?? 03 05 ?? ?? 40 00 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}