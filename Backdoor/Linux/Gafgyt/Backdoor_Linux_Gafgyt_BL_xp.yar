
rule Backdoor_Linux_Gafgyt_BL_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BL!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {02 24 00 00 62 a0 18 00 c2 8f 00 } //01 00 
		$a_00_1 = {e0 99 03 50 f8 bd 27 ac 07 bf af a8 07 be af a4 07 b1 af } //01 00 
		$a_00_2 = {dc 8f 21 18 40 00 3c 82 } //01 00 
		$a_00_3 = {80 18 02 00 21 10 43 00 21 18 40 00 18 86 82 8f 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}