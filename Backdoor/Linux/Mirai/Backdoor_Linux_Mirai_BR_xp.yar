
rule Backdoor_Linux_Mirai_BR_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BR!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {02 40 00 92 10 00 02 80 a0 40 0a 02 80 00 08 84 00 a0 08 86 00 e0 01 80 a0 c0 08 32 bf ff fa c2 08 a0 04 81 c3 e0 08 90 10 00 0b d6 02 40 00 81 c3 e0 08 90 10 00 0b } //1
		$a_00_1 = {04 80 00 2a b0 10 00 08 80 a4 a0 01 02 80 00 31 80 a4 a0 02 c2 0c 20 01 02 80 00 2e c2 2a 20 04 b2 04 bf } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}