
rule Backdoor_Linux_Mirai_CO_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {30 43 e2 19 00 53 e3 0c 20 c9 97 05 3a 8d 92 6c c1 93 95 05 ea 8d e2 01 c0 8c e2 6c c1 8e e5 ee ff ff ea 24 00 a0 e3 f6 2a 00 eb 25 00 a0 e3 f4 2a 00 } //1
		$a_00_1 = {a0 e1 2c 00 8d e5 28 10 8d e5 16 20 a0 e3 00 30 a0 e3 04 00 a0 e1 05 10 a0 e1 57 07 00 eb 05 10 a0 e1 3c 00 8d e5 15 20 a0 e3 04 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}