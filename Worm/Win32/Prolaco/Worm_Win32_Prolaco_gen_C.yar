
rule Worm_Win32_Prolaco_gen_C{
	meta:
		description = "Worm:Win32/Prolaco.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 45 08 32 04 32 88 04 0a 42 39 da 75 f2 } //2
		$a_03_1 = {68 00 00 00 80 53 e8 ?? ?? ?? ?? 89 c3 56 6a 00 50 e8 ?? ?? ?? ?? 89 c6 51 53 e8 ?? ?? ?? ?? 83 c4 ?? 81 fe ?? ?? ?? ?? (7e|74) ?? 81 fe ?? ?? ?? ?? 7e } //2
		$a_03_2 = {80 fa 61 74 ?? 80 fa 62 74 ?? 83 ec ?? 56 e8 ?? ?? ?? ?? 83 c4 ?? 83 f8 02 75 } //1
		$a_02_3 = {83 c4 0c 6a 40 68 00 30 00 00 ff 70 50 ff 70 34 ff ?? ?? ff 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 6a 00 ff 70 54 57 ff 70 34 ff ?? ?? ff 95 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_02_3  & 1)*2) >=3
 
}