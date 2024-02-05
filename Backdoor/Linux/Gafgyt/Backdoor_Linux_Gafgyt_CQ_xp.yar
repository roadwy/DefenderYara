
rule Backdoor_Linux_Gafgyt_CQ_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CQ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {fe 8f 83 80 18 00 02 20 80 24 62 1a ac 00 82 10 21 8c 42 } //01 00 
		$a_00_1 = {00 8c 42 0e 88 8f 83 80 18 00 02 20 80 24 62 1a ac 00 82 10 21 8c 44 } //01 00 
		$a_00_2 = {00 38 12 00 00 30 10 00 a6 28 21 00 a0 30 21 8f 82 80 18 00 } //01 00 
		$a_00_3 = {00 34 af c6 00 38 af c7 00 3c af c0 00 24 24 02 00 20 af c2 00 20 8f c2 00 } //00 00 
	condition:
		any of ($a_*)
 
}