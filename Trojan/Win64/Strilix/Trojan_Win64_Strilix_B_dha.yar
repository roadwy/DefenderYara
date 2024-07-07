
rule Trojan_Win64_Strilix_B_dha{
	meta:
		description = "Trojan:Win64/Strilix.B!dha,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 4c 24 24 48 8b 0d 91 58 01 00 c7 44 24 20 10 00 00 00 c7 44 24 28 07 00 00 00 44 89 44 24 34 c7 44 24 38 b8 0b 00 00 } //10
		$a_01_1 = {41 b8 8d 56 e6 8c 41 8b c0 f7 e9 03 d1 c1 fa 0b 8b c2 c1 e8 1f 03 d0 69 c2 89 0e 00 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}