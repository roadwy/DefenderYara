
rule Backdoor_Linux_Mirai_IU_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 d0 8d e2 f0 8f bd e8 0a 00 0a 00 34 2e 30 30 32 30 32 31 0a 00 00 00 14 30 8d e5 04 60 8e e2 00 50 a0 e3 00 40 e0 e3 03 20 a0 e3 00 10 96 e5 00 00 a0 e3 0c 10 8d e5 c0 70 a0 e3 00 00 00 ef 08 00 8d e5 00 30 96 e5 04 30 2d e5 0d 30 a0 e1 00 20 a0 e1 08 00 d6 e5 } //1
		$a_03_1 = {18 d0 4d e2 b0 02 00 eb 00 c0 dd e5 0e 00 5c e3 78 ?? ?? ?? 0c 48 2d e9 00 b0 d0 e5 06 cc a0 e3 ab b1 a0 e1 1c cb a0 e1 0d b0 a0 e1 3a cd 8c e2 0c d0 4d e0 00 c0 93 e5 08 30 8d e5 04 c0 8d e5 00 20 8d e5 0c 30 8d e2 00 c0 a0 e3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}