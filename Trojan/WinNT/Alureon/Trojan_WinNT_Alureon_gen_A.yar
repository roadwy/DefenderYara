
rule Trojan_WinNT_Alureon_gen_A{
	meta:
		description = "Trojan:WinNT/Alureon.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 06 2b c2 33 c7 89 06 03 bb ?? ?? ?? ?? 03 93 ?? ?? ?? ?? 87 fa 83 c6 04 83 e9 04 75 e2 } //2
		$a_01_1 = {8d 9e f8 00 00 00 0f b7 56 06 8b 73 14 8b 7b 0c } //1
		$a_03_2 = {c1 e9 02 6a 00 e2 fc 83 c4 ?? ff e0 } //1
		$a_01_3 = {60 50 0f 01 4c 24 fe 5e 8b 5e 04 66 8b 1e } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}