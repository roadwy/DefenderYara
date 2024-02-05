
rule Backdoor_Linux_Dklkt_A_xp{
	meta:
		description = "Backdoor:Linux/Dklkt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 44 4f 53 5f 53 54 4f 50 } //01 00 
		$a_01_1 = {42 49 47 5f 46 6c 6f 6f 64 } //01 00 
		$a_01_2 = {54 63 70 46 6c 6f 6f 64 } //01 00 
		$a_01_3 = {55 64 70 46 6c 6f 6f 64 } //01 00 
		$a_01_4 = {72 6d 20 2d 72 66 20 2e 62 36 34 } //01 00 
		$a_01_5 = {3a 53 49 4d 50 4c 45 5f 44 44 4f 53 } //00 00 
	condition:
		any of ($a_*)
 
}