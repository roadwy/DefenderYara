
rule Misleading_Linux_Chisel_A_MTB{
	meta:
		description = "Misleading:Linux/Chisel.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 75 74 69 6c 2e 4e 65 77 53 69 6e 67 6c 65 48 6f 73 74 52 65 76 65 72 73 65 50 72 6f 78 79 } //01 00 
		$a_01_1 = {63 68 69 73 65 6c 2f 73 68 61 72 65 2f 74 75 6e 6e 65 6c 2f 74 75 6e 6e 65 6c 2e 67 6f } //01 00 
		$a_01_2 = {63 68 69 73 65 6c 2f 73 65 72 76 65 72 2e 4e 65 77 53 65 72 76 65 72 } //01 00 
		$a_01_3 = {74 75 6e 6e 65 6c 2e 28 2a 54 75 6e 6e 65 6c 29 2e 6b 65 65 70 41 6c 69 76 65 4c 6f 6f 70 } //00 00 
	condition:
		any of ($a_*)
 
}