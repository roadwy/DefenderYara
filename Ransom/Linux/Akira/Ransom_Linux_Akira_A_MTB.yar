
rule Ransom_Linux_Akira_A_MTB{
	meta:
		description = "Ransom:Linux/Akira.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6b 69 72 61 5f 72 65 61 64 6d 65 2e 74 78 74 } //01 00 
		$a_01_1 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 61 74 68 } //01 00 
		$a_01_2 = {2d 2d 73 68 61 72 65 5f 66 69 6c 65 } //01 00 
		$a_01_3 = {2e 61 6b 69 72 61 } //01 00 
		$a_01_4 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 65 72 63 65 6e 74 } //01 00 
		$a_03_5 = {74 74 70 73 3a 2f 2f 90 02 58 2e 6f 6e 69 6f 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}