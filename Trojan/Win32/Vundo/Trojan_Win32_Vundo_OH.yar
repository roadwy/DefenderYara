
rule Trojan_Win32_Vundo_OH{
	meta:
		description = "Trojan:Win32/Vundo.OH,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 10 c1 e1 10 0b c1 89 45 ?? 2d ?? ?? 00 00 89 45 ?? 8b c8 c1 e9 1c c1 e0 04 0b c8 89 4d ?? 33 ca 89 4d ?? 89 0c 96 42 eb } //8
		$a_01_1 = {0f 85 a8 00 00 00 81 f9 c6 74 8c 3d 0f 84 c5 00 00 00 81 f9 25 19 fa b6 0f 84 b9 00 00 00 81 f9 a1 b7 ad b8 } //4
		$a_03_2 = {8b f9 c1 ef 17 c1 e1 09 0b cf 89 4d ?? 81 e9 ?? ?? ?? 00 89 4d ?? 0f b6 d2 2b ca e9 } //4
		$a_01_3 = {00 80 55 aa 68 1c 27 c0 00 20 4c aa 93 8c 2f ea 13 8c 26 e5 45 09 } //2
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*4+(#a_03_2  & 1)*4+(#a_01_3  & 1)*2) >=10
 
}