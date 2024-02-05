
rule Ransom_Linux_Hive_B_MTB{
	meta:
		description = "Ransom:Linux/Hive.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 70 6f 77 65 72 2e 6f 66 66 } //01 00 
		$a_01_1 = {2b 65 6e 63 72 79 70 74 20 25 73 } //01 00 
		$a_01_2 = {68 69 76 65 } //01 00 
		$a_03_3 = {74 74 70 3a 2f 2f 90 02 58 2e 6f 6e 69 6f 6e 2f 90 00 } //01 00 
		$a_01_4 = {48 4f 57 5f 54 4f 5f 44 45 43 52 59 50 54 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}