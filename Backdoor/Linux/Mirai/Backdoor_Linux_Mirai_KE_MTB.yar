
rule Backdoor_Linux_Mirai_KE_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c0 2f a0 e1 00 10 81 e0 c1 27 62 e0 04 30 97 e5 02 00 80 e0 00 08 a0 e1 14 30 83 e2 20 c4 a0 e1 03 18 a0 e1 ff cc 0c e2 20 cc 8c e1 21 24 a0 e1 b2 c0 c5 e1 ff 2c 02 e2 00 c0 a0 e3 21 2c 82 e1 b0 c1 c5 e1 05 10 a0 e1 06 00 a0 e1 } //1
		$a_01_1 = {0f 00 00 e2 57 0e 80 e2 08 00 80 e2 00 08 a0 e1 20 34 a0 e1 ff 3c 03 e2 20 3c 83 e1 04 20 a0 e3 ba 32 c8 e1 2c 20 c8 e5 08 30 a0 e3 0a 20 a0 e3 2e 30 c8 e5 2f 20 c8 e5 2d 50 c8 e5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}