
rule Backdoor_Linux_Gafgyt_Z_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.Z!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 51 5a 49 51 5a 4c 51 5a 4c 51 5a 41 51 5a 54 51 5a 54 51 5a 4b } //01 00 
		$a_01_1 = {4c 51 5a 4f 51 5a 4c 51 5a 4e 51 5a 4f 51 5a 47 51 5a 54 51 5a 46 51 5a 4f } //01 00 
		$a_01_2 = {55 51 5a 44 51 5a 50 } //00 00 
		$a_00_3 = {5d 04 00 } //00 de 
	condition:
		any of ($a_*)
 
}