
rule Backdoor_Linux_Ibiru_A_xp{
	meta:
		description = "Backdoor:Linux/Ibiru.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 61 70 69 62 69 72 75 } //01 00 
		$a_01_1 = {6b 46 62 69 6e 64 } //01 00 
		$a_01_2 = {46 75 63 6b 20 4f 66 66 20 54 68 69 73 20 4d 61 63 68 69 6e 65 } //01 00 
		$a_01_3 = {50 61 72 61 6e 6f 69 61 20 53 65 63 72 65 74 } //01 00 
		$a_01_4 = {62 69 6e 64 61 72 79 2e 63 } //00 00 
	condition:
		any of ($a_*)
 
}