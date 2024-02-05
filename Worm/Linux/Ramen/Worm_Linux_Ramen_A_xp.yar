
rule Worm_Linux_Ramen_A_xp{
	meta:
		description = "Worm:Linux/Ramen.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 73 61 67 65 3a 20 25 73 20 61 64 64 72 65 73 73 20 5b 2d 73 5d 5b 2d 65 5d } //01 00 
		$a_01_1 = {6d 61 69 6c 20 68 75 63 6b 69 74 40 63 68 69 6e 61 2e 63 6f 6d 20 3c 31 69 30 6e } //01 00 
		$a_01_2 = {65 78 70 6c 6f 69 74 20 70 61 63 6b 65 74 } //01 00 
		$a_01_3 = {6b 69 6c 6c 61 6c 6c 20 2d 48 55 50 20 69 6e 65 74 64 } //01 00 
		$a_01_4 = {63 68 6d 6f 64 20 37 35 35 20 6c 69 6f 6e } //01 00 
		$a_01_5 = {72 6d 20 2d 66 72 20 31 69 30 6e } //00 00 
	condition:
		any of ($a_*)
 
}