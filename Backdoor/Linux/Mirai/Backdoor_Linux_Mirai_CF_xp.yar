
rule Backdoor_Linux_Mirai_CF_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CF!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {20 a0 e3 12 a1 a0 e1 a6 32 a0 e1 03 31 a0 e1 94 20 8d e2 02 70 83 e0 8c c0 17 e5 01 80 86 e2 0a c0 8c e1 8c c0 } //1
		$a_00_1 = {c0 d2 e5 02 00 81 e2 01 e0 d7 e5 00 a0 d7 e5 0c 54 8b e1 02 b0 d1 e5 01 c0 d0 e5 02 80 d2 e5 02 20 80 e2 02 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}