
rule Trojan_Win64_Alureon_gen_L{
	meta:
		description = "Trojan:Win64/Alureon.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b ca b8 55 aa 00 00 d1 e9 03 ca b2 80 c1 e9 05 6b c9 3f 2b d9 b9 f7 00 00 00 f3 a4 fe c3 b1 2a } //1
		$a_01_1 = {b8 53 46 00 00 66 39 03 74 0a b8 53 44 00 00 66 39 03 75 } //1
		$a_03_2 = {48 83 c2 28 8b c8 41 ff c0 f3 a4 8b 7a 04 48 8b 4d ?? 41 0f b7 44 24 06 48 03 f9 44 3b c0 72 cf } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}