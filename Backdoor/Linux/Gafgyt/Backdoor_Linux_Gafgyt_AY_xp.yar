
rule Backdoor_Linux_Gafgyt_AY_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AY!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 50 46 4c 4f 4f 44 } //01 00 
		$a_01_1 = {62 75 73 79 62 6f 78 20 77 67 65 74 } //01 00 
		$a_01_2 = {54 43 50 46 4c 4f 4f 44 } //00 00 
	condition:
		any of ($a_*)
 
}