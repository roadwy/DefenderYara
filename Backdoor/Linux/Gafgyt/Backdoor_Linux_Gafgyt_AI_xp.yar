
rule Backdoor_Linux_Gafgyt_AI_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AI!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 45 36 4d 47 41 62 49 } //01 00 
		$a_01_1 = {74 63 70 72 61 77 } //01 00 
		$a_01_2 = {69 63 6d 70 65 63 68 6f } //01 00 
		$a_01_3 = {75 64 70 70 6c 61 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}