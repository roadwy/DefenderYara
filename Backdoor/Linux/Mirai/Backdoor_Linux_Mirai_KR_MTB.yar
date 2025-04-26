
rule Backdoor_Linux_Mirai_KR_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 10 a0 e3 04 00 a0 e1 76 08 00 eb dc 30 9f e5 00 20 a0 e3 03 30 8f e0 14 30 8d e5 d0 30 9f e5 1c 50 8d e5 03 30 8f e0 18 30 8d e5 c4 30 9f e5 20 20 8d e5 c0 10 9f e5 03 30 9a e7 01 10 8f e0 0c 00 8d e2 00 30 93 e5 04 30 8d e5 14 30 8d e2 00 30 8d e5 04 30 a0 e1 ed 07 00 eb 00 50 a0 e1 04 00 a0 e1 57 08 00 eb 00 00 55 e3 } //1
		$a_01_1 = {f0 47 2d e9 41 de 4d e2 08 d0 4d e2 4a 6f 8d e2 00 50 a0 e1 88 20 a0 e3 00 10 a0 e3 06 00 a0 e1 69 02 00 eb 01 40 a0 e3 00 30 e0 e3 b0 a1 9f e5 24 41 8d e5 10 30 8d e5 0f 05 00 eb 00 00 55 e3 0a a0 8f e0 04 00 a0 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}