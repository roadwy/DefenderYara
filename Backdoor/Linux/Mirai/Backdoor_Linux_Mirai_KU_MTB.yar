
rule Backdoor_Linux_Mirai_KU_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {18 20 a0 e3 9a 02 02 e0 18 c0 9d e5 02 70 8b e0 04 30 d7 e5 0a 51 9c e7 1f 00 53 e3 14 60 85 e2 28 80 85 e2 10 00 00 8a 02 40 9b e7 01 08 00 eb ff 38 04 e2 24 2c a0 e1 23 24 82 e1 ff 3c 04 e2 03 24 82 e1 04 30 d7 e5 04 2c 82 e1 30 23 82 e0 ff 18 02 e2 22 3c a0 e1 21 34 83 e1 ff 1c 02 e2 01 34 83 e1 } //1
		$a_01_1 = {00 08 a0 e1 20 28 a0 e1 08 10 88 e2 01 18 a0 e1 21 34 a0 e1 22 04 a0 e1 ff 3c 03 e2 ff 20 02 e2 02 04 80 e1 } //1
		$a_01_2 = {21 3c 83 e1 b4 30 c6 e1 b2 00 c6 e1 01 70 87 e2 18 a0 8a e2 14 00 9d e5 00 00 57 e1 96 ff ff 1a 34 10 9d e5 00 a0 a0 e3 08 10 81 e2 10 10 8d e5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}