
rule Backdoor_Linux_Mirai_HS_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {90 0a 20 ff 94 0a a0 ff 10 80 00 09 84 10 20 00 84 00 a0 01 80 a0 40 0a 82 10 00 09 12 80 00 04 92 02 60 08 10 80 00 05 d6 00 40 00 80 a0 80 08 26 bf ff f8 c2 0a 60 04 } //1
		$a_00_1 = {82 08 40 03 84 00 80 04 82 06 80 01 82 00 40 1c 10 80 00 03 82 00 40 02 82 00 c0 02 85 30 60 10 80 a0 a0 00 12 bf ff fd 86 08 40 1b b0 38 00 01 b1 2e 20 10 b1 36 20 10 81 c7 e0 08 81 e8 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}