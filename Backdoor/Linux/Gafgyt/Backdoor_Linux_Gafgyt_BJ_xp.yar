
rule Backdoor_Linux_Gafgyt_BJ_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BJ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 41 52 33 2e 39 31 57 41 52 } //01 00 
		$a_01_1 = {48 4f 4c 44 } //01 00 
		$a_01_2 = {42 4f 47 4f 4d 49 50 53 } //02 00 
		$a_01_3 = {4b 49 4c 4c 41 54 } //00 00 
	condition:
		any of ($a_*)
 
}