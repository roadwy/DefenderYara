
rule Trojan_Win64_Mikey_LMF_MTB{
	meta:
		description = "Trojan:Win64/Mikey.LMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 74 89 44 24 60 65 48 8b 04 25 58 00 00 00 41 8b c9 41 ba 98 12 00 00 48 8b 14 c8 b9 a0 12 00 00 8b 04 11 a8 01 } //10
		$a_01_1 = {48 b8 fb 82 e4 08 c1 3b e9 c5 48 89 44 24 30 48 8b 44 24 30 48 89 4c 24 30 49 8d 4b 98 48 89 44 24 50 48 8b 44 24 30 c5 fe 6f 44 24 60 48 89 44 24 58 c5 fd ef 4c 24 40 } //20
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}