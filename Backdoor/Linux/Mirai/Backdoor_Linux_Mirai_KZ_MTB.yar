
rule Backdoor_Linux_Mirai_KZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 30 8c e2 c3 2f a0 e1 22 2c a0 e1 02 30 83 e0 ff 30 03 e2 03 c0 62 e0 b5 2f 8d e2 0c 00 82 e0 c0 32 50 e5 03 30 8e e0 c3 1f a0 e1 21 1c a0 e1 01 30 83 e0 ff 30 03 e2 03 e0 61 e0 0e 30 d7 e7 0c 20 d7 e7 03 20 22 e0 0c 20 c7 e7 0e 30 d7 e7 03 20 22 e0 0e 20 c7 e7 0c 30 d7 e7 } //1
		$a_01_1 = {0e 20 c7 e7 0c 30 d7 e7 03 20 22 e0 0c 20 c7 e7 b5 3f 8d e2 0e 10 83 e0 c0 22 51 e5 c0 32 50 e5 02 30 83 e0 ff 30 03 e2 b5 1f 8d e2 03 20 81 e0 c0 12 52 e5 05 30 d4 e7 01 30 23 e0 05 30 c4 e7 01 40 84 e2 04 00 56 e1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}