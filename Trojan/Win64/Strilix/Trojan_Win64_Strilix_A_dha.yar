
rule Trojan_Win64_Strilix_A_dha{
	meta:
		description = "Trojan:Win64/Strilix.A!dha,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 b8 8d 56 e6 8c 41 8b c0 f7 e9 03 d1 c1 fa 0b 8b c2 c1 e8 1f 03 d0 69 c2 89 0e 00 00 } //0a 00 
		$a_01_1 = {48 89 b8 08 01 00 00 c7 00 44 33 22 11 48 89 b0 d8 00 00 00 48 89 70 10 48 89 70 18 89 70 20 48 89 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}