
rule Backdoor_Linux_Gafgyt_CK_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CK!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {30 4b e5 43 34 a0 e1 2f 30 4b e5 68 32 1b e5 03 38 a0 e1 23 38 a0 e1 2e 30 4b e5 43 34 a0 e1 2d 30 4b e5 00 30 a0 e3 14 30 0b e5 cc 30 9f e5 26 } //00 00 
	condition:
		any of ($a_*)
 
}