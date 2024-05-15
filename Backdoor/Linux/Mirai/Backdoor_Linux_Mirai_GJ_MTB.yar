
rule Backdoor_Linux_Mirai_GJ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GJ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f0 35 9f e5 02 00 5c e1 03 30 98 e7 00 c0 a0 23 1c 10 a0 e3 9c 31 23 e0 64 c0 8d e5 68 c0 9d e5 01 20 8c e2 10 00 9d e5 02 28 a0 e1 22 28 a0 e1 68 20 8d e5 0c 10 9d e5 b0 20 88 e1 64 20 9d e5 01 20 88 e7 03 e0 a0 e1 0f 00 be e8 } //01 00 
		$a_01_1 = {1c 00 90 e5 04 10 a0 e1 a9 04 00 eb 00 00 55 e3 44 51 84 e5 1c 00 94 05 f9 04 00 0b 04 d0 8d e2 30 40 bd e8 1e ff 2f e1 } //00 00 
	condition:
		any of ($a_*)
 
}