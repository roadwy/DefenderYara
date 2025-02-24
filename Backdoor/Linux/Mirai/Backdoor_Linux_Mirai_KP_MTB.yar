
rule Backdoor_Linux_Mirai_KP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {bc 01 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 10 80 bd e8 10 40 2d e9 16 00 90 ef 01 0a 70 e3 00 40 a0 e1 } //1
		$a_01_1 = {40 30 9f e5 05 00 a0 e1 00 20 93 e5 3c 10 9f e5 01 3a a0 e3 94 ff ff eb 01 10 a0 e3 00 40 a0 e1 2c 30 9f e5 0d 00 a0 e1 0f e0 a0 e1 03 f0 a0 e1 04 00 a0 e1 10 d0 8d e2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}