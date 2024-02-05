
rule DDoS_Linux_Sfloost_A_xp{
	meta:
		description = "DDoS:Linux/Sfloost.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 64 65 6c 61 6c 6c 6d 79 6b 6b 6b } //01 00 
		$a_01_1 = {44 6e 73 46 6c 6f 6f 64 53 65 6e 64 54 68 72 65 61 64 } //01 00 
		$a_01_2 = {72 6d 20 2d 66 20 2f 65 74 63 2f 72 63 2e 64 2f 69 6e 69 74 2e 64 2f 49 70 74 61 62 4c 65 73 } //01 00 
		$a_01_3 = {53 79 6e 46 6c 6f 6f 64 42 75 69 6c 64 54 68 72 65 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}