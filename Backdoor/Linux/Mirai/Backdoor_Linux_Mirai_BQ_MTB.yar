
rule Backdoor_Linux_Mirai_BQ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {05 30 dc e7 00 00 53 e3 2e 00 53 13 00 40 c6 05 01 30 42 15 01 60 a0 01 00 40 a0 03 ff 40 0e 12 01 c0 8c e2 01 20 82 e2 00 30 6c e0 00 00 53 e3 01 e0 84 e2 01 10 42 e2 f0 ff ff ca } //1
		$a_00_1 = {06 30 d2 e7 22 30 23 e2 06 30 c2 e7 01 20 82 e2 07 00 52 e1 f9 ff ff 1a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}