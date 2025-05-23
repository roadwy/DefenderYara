
rule Trojan_Win64_Musixk_A{
	meta:
		description = "Trojan:Win64/Musixk.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 08 00 00 00 00 c7 44 24 08 ?? ?? ?? ?? 8b 44 24 08 35 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 44 24 08 8b 44 24 08 } //3
		$a_01_1 = {48 8d 44 24 58 c7 44 24 58 41 00 45 00 c7 44 24 5c 53 00 00 00 48 8d 4d ef 48 89 44 24 50 45 33 c9 48 8b 54 24 50 45 33 c0 ff d7 } //3
		$a_03_2 = {8d 77 01 4c 8d 3c c5 00 00 00 00 4c 8d 2d ?? ?? ?? ?? 66 0f 1f [0-07] 8b e6 } //2
		$a_03_3 = {0f b6 07 84 c0 74 ?? 3c 20 74 ?? 8b [0-0a] 41 ff c0 48 ff c7 } //2
		$a_01_4 = {65 48 8b 04 25 60 00 00 00 83 b8 18 01 00 00 06 74 0e 83 b8 18 01 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1) >=6
 
}