
rule Trojan_Win64_Phonzy_AHB_MTB{
	meta:
		description = "Trojan:Win64/Phonzy.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 f1 20 83 b8 ed f6 c2 01 0f 44 c8 8b c1 d1 e8 8b d0 81 f2 20 83 b8 ed f6 c1 01 0f 44 d0 8b ca d1 e9 8b c1 35 20 83 b8 ed f6 c2 01 0f 44 c1 41 0f b7 08 66 85 c9 0f } //3
		$a_01_1 = {c7 44 24 50 0c 00 00 00 66 48 0f 7e c8 48 c1 e8 20 89 44 24 54 66 0f 6f c1 66 0f 73 d8 08 66 0f 7e 44 24 58 66 0f 73 d9 08 66 48 0f 7e c8 48 c1 e8 20 89 44 24 5c 89 4c 24 60 48 8d 4c 24 50 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}