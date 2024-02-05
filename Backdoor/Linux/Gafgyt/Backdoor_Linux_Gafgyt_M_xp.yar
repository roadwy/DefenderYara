
rule Backdoor_Linux_Gafgyt_M_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.M!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 74 61 72 74 54 68 65 4c 65 6c 7a } //01 00 
		$a_00_1 = {73 65 6e 64 55 44 50 } //01 00 
		$a_00_2 = {73 65 6e 64 54 43 50 } //00 00 
		$a_00_3 = {5d 04 00 } //00 26 
	condition:
		any of ($a_*)
 
}