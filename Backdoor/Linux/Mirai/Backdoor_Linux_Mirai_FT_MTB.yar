
rule Backdoor_Linux_Mirai_FT_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {02 10 41 e2 b2 30 d0 e0 01 00 51 e3 03 20 82 e0 fa ?? ?? ?? 01 00 51 e3 00 30 d0 05 03 20 82 00 02 08 a0 e1 20 08 a0 e1 22 08 80 e0 20 08 80 e0 00 00 e0 e1 00 08 a0 e1 20 08 a0 e1 1e ff 2f e1 } //1
		$a_00_1 = {00 30 85 e5 00 30 9c e5 00 30 84 e5 00 20 9c e5 00 30 9c e5 a2 39 23 e0 00 30 8c e5 00 20 9c e5 8e e5 2e e0 02 20 2e e0 2e 24 22 e0 00 20 8c e5 00 30 9c e5 04 d0 4d e2 00 40 a0 e1 01 10 60 e0 03 00 a0 e1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}