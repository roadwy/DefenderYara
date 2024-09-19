
rule Backdoor_Linux_Mirai_IZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 40 2d e9 18 40 80 e2 10 d0 4d e2 ac 10 9f e5 04 20 a0 e1 a8 30 9f e5 00 50 a0 e1 0d 00 a0 e1 0f e0 a0 e1 03 f0 a0 e1 04 00 a0 e1 94 30 9f e5 0f e0 a0 e1 03 f0 a0 e1 00 60 a0 e3 } //1
		$a_03_1 = {22 3c 8d e2 02 00 81 e2 24 30 83 e2 00 20 83 e0 21 32 52 e5 00 00 53 e3 20 00 53 13 00 50 a0 01 07 ?? ?? ?? 01 20 86 e0 00 50 a0 e1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}