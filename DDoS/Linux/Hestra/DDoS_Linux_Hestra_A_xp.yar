
rule DDoS_Linux_Hestra_A_xp{
	meta:
		description = "DDoS:Linux/Hestra.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 65 73 74 72 61 2e 63 } //01 00 
		$a_01_1 = {55 73 61 67 65 3a 20 3c 68 65 73 74 72 61 3e 20 3c 68 6f 73 74 3e 20 3c 70 6f 72 74 3e } //01 00 
		$a_01_2 = {45 78 74 72 65 6d 65 6c 79 20 44 61 6e 67 65 72 6f 75 73 20 74 6f 6f 6c } //01 00 
		$a_01_3 = {46 75 78 30 72 69 6e 67 20 25 73 20 6f 6e 20 70 6f 72 74 20 25 64 } //00 00 
	condition:
		any of ($a_*)
 
}