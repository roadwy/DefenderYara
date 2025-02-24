
rule Backdoor_Linux_Mirai_KI_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 a7 10 21 80 43 00 00 00 00 00 00 14 60 ff fc 24 e7 00 01 24 e7 ff ff 10 00 00 04 00 e0 18 21 } //1
		$a_01_1 = {03 20 f8 09 00 00 00 00 3c 04 80 80 34 84 80 81 00 44 00 18 00 02 2f c3 8f bc 00 18 8f a6 00 38 02 a0 20 21 03 c0 c8 21 00 00 18 10 00 62 18 21 00 03 19 c3 00 65 18 23 00 03 2a 00 00 a3 28 23 03 20 f8 09 00 45 28 23 8f bc 00 18 16 c0 00 3e a6 00 00 02 02 00 28 21 02 40 20 21 00 00 30 21 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}