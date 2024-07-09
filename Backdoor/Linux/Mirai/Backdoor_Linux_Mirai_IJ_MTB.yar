
rule Backdoor_Linux_Mirai_IJ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IJ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 51 e3 01 10 41 e2 0f ?? ?? ?? 01 c0 d0 e4 41 30 4c e2 19 00 53 e3 02 30 d4 e7 41 e0 43 e2 60 c0 8c 93 19 00 5e e3 60 30 83 93 03 00 5c e1 00 20 a0 13 f1 ?? ?? ?? 01 20 82 e2 02 00 55 e1 ee ?? ?? ?? 00 00 66 e0 70 80 bd e8 } //1
		$a_03_1 = {01 30 cc e7 00 20 9e e5 02 30 dc e7 03 30 25 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 24 e0 01 30 cc e7 04 20 de e5 01 30 d7 e5 01 c0 8c e2 03 24 82 e1 0c 00 52 e1 e9 ?? ?? ?? f0 80 bd e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}