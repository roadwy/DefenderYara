
rule Backdoor_Linux_Gafgyt_CM_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CM!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 04 24 21 28 40 00 01 00 06 24 7c 83 99 8f 00 00 00 00 09 f8 20 03 } //01 00 
		$a_00_1 = {21 28 40 00 20 80 82 8f 00 00 00 00 58 09 59 24 09 f8 20 03 } //00 00 
	condition:
		any of ($a_*)
 
}