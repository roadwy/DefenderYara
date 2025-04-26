
rule Backdoor_Linux_Mirai_KG_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {93 61 16 62 05 79 10 61 70 39 22 23 04 73 10 23 ec 73 02 e1 11 23 04 73 22 23 fb 7c f0 ?? 24 73 } //1
		$a_01_1 = {20 d0 0b 40 09 00 f8 7f 00 e1 12 20 0c e0 a2 2f fc 01 f6 56 1c 65 1b d1 b1 1f f4 57 0b 41 83 64 08 7f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Backdoor_Linux_Mirai_KG_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.KG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {1c 00 51 e3 11 ?? ?? ?? 10 20 a0 e3 30 10 9d e5 08 00 a0 e1 87 0b 00 eb 0a 30 a0 e3 14 e0 9d e5 08 30 87 e5 06 30 83 e2 0c 30 87 e5 44 00 9d e5 00 50 87 e5 10 e0 87 e5 ac 00 00 eb 00 30 a0 e3 74 20 9d e5 03 00 a0 e1 00 70 82 e5 } //1
		$a_01_1 = {34 40 9f e5 03 c0 80 e0 02 00 a0 e1 2c 30 9f e5 2c 20 9f e5 04 40 8f e0 03 30 84 e0 02 20 84 e0 08 c0 8d e5 18 00 00 eb 14 00 9d e5 18 d0 8d e2 10 40 bd e8 1e ff 2f e1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}