
rule Backdoor_Linux_Mirai_BZ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BZ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 84 e5 02 10 c4 e5 10 20 93 e5 14 10 84 e2 40 c4 a0 e1 58 30 a0 e3 05 c0 c4 e5 04 00 c4 e5 03 30 c1 e5 0d } //01 00 
		$a_00_1 = {30 c0 e5 26 30 d4 e5 b0 30 c3 e3 40 30 83 e3 26 30 c4 e5 14 30 9d e5 1c 10 87 } //00 00 
	condition:
		any of ($a_*)
 
}