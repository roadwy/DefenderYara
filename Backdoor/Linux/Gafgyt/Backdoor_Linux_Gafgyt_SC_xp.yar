
rule Backdoor_Linux_Gafgyt_SC_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.SC!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 56 48 55 44 50 } //01 00 
		$a_01_1 = {64 72 6f 70 62 65 61 72 } //01 00 
		$a_01_2 = {2e 4b 49 4c 4c 46 4c 4f 4f 44 53 } //01 00 
		$a_01_3 = {2e 4b 49 4c 4c 50 49 44 } //01 00 
		$a_01_4 = {5b 33 37 6d 43 69 70 68 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}