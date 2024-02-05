
rule Backdoor_Linux_Gafgyt_BQ_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BQ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {7d 0c 00 01 80 fc 00 01 83 d0 00 01 85 34 00 01 86 b0 00 01 88 14 00 01 89 90 00 01 8c 9c 9d e3 bf } //00 00 
	condition:
		any of ($a_*)
 
}