
rule Backdoor_Linux_Mirai_HW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0d 00 00 da 04 30 d1 e5 02 00 53 e1 08 c0 81 12 00 e0 a0 13 04 00 00 1a 09 00 00 ea 04 30 dc e5 02 00 53 e1 08 c0 8c e2 05 00 00 0a 01 e0 8e e2 00 00 5e e1 0c 10 a0 e1 f7 ff ff 1a 04 00 a0 e1 10 80 bd e8 00 40 91 e5 04 00 a0 e1 10 80 bd e8 } //1
		$a_00_1 = {0e 00 00 da 5c 30 9f e5 00 20 93 e5 00 c0 92 e5 04 30 dc e5 07 00 53 e1 05 00 a0 11 04 00 00 1a 08 00 00 ea 00 c1 92 e7 04 30 dc e5 07 00 53 e1 04 00 00 0a 01 00 80 e2 01 00 50 e1 f8 ff ff 1a 00 00 a0 e3 51 ff ff eb } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}