
rule Backdoor_Linux_Roopre_B_xp{
	meta:
		description = "Backdoor:Linux/Roopre.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 64 65 76 2f 6e 75 6c 6c 00 25 73 2f 25 63 2e 25 64 00 41 55 00 28 6e 75 6c 6c 29 00 52 4f 4f 54 00 4c 44 5f 50 52 45 4c 4f 41 44 00 2f 75 73 72 2f 62 69 6e 2f 75 6e 61 6d 65 20 2d 61 00 2f 2f 00 2e 00 2f 74 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}