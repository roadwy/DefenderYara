
rule Backdoor_Linux_Gafgyt_BD_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BD!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {57 41 52 33 2e 39 31 57 41 52 } //02 00 
		$a_01_1 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 38 39 2e 33 34 2e 39 37 2e 31 31 35 } //01 00 
		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } //01 00 
		$a_01_3 = {55 44 50 46 4c 4f 4f 44 } //01 00 
		$a_01_4 = {4b 49 4c 4c 41 54 54 } //00 00 
	condition:
		any of ($a_*)
 
}