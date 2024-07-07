
rule Backdoor_Linux_Mirai_JZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {93 36 60 10 40 00 0c c3 90 10 00 10 94 10 00 1a d0 06 c0 12 92 10 00 10 40 00 26 95 17 00 00 10 a8 05 20 01 80 a5 00 18 02 bf ff dd b6 06 e0 04 10 bf ff f4 } //1
		$a_00_1 = {e2 06 c0 13 92 10 23 e8 40 00 0c 39 90 10 22 bc a1 2a 20 10 90 10 00 11 a1 34 20 10 40 00 0c 53 92 10 00 10 94 10 00 10 d0 06 c0 12 92 10 00 11 40 00 26 25 17 00 00 10 b4 06 a0 01 80 a6 80 18 12 bf ff f0 b6 06 e0 04 80 a6 20 00 04 bf ff ea b4 10 20 00 10 bf ff eb } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}