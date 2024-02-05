
rule Backdoor_Linux_Mirai_BW_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BW!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {30 d6 e5 1f 00 53 e3 12 00 00 8a 10 40 96 e5 76 1e 00 eb } //01 00 
		$a_00_1 = {19 30 96 e5 00 00 53 e3 04 30 a0 13 93 35 46 15 93 35 46 05 55 ff ff 0a 00 30 e0 e3 00 50 a0 } //00 00 
	condition:
		any of ($a_*)
 
}