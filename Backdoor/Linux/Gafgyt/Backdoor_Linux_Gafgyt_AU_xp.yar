
rule Backdoor_Linux_Gafgyt_AU_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AU!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 2a 5e 6f 2a 5e 74 2a 5e 3a 2a 5e 20 2a 5e 25 2a 5e 73 2a 5e 5c 2a 5e 6e } //01 00 
		$a_00_1 = {4c 2a 5e 49 2a 5e 4c 2a 5e 42 2a 5e 49 2a 5e 54 2a 5e 43 2a 5e 48 } //01 00 
		$a_00_2 = {55 2a 5e 44 2a 5e 50 } //01 00 
		$a_00_3 = {4b 2a 5e 49 2a 5e 4c 2a 5e 4c } //01 00 
		$a_00_4 = {4c 2a 5e 55 2a 5e 43 2a 5e 4b 2a 5e 59 2a 5e 4c 2a 5e 49 2a 5e 4c 2a 5e 44 2a 5e 55 2a 5e 44 2a 5e 45 } //00 00 
	condition:
		any of ($a_*)
 
}