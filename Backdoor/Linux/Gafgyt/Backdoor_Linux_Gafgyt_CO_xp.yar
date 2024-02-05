
rule Backdoor_Linux_Gafgyt_CO_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CO!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 20 8f c4 00 20 8f 85 82 10 8f 99 81 e0 00 00 00 00 03 20 f8 09 00 } //01 00 
		$a_00_1 = {00 62 10 21 8c 42 00 00 8f c4 00 30 00 40 28 21 8f 99 83 48 00 } //00 00 
	condition:
		any of ($a_*)
 
}