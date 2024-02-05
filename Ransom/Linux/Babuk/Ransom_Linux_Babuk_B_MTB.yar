
rule Ransom_Linux_Babuk_B_MTB{
	meta:
		description = "Ransom:Linux/Babuk.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 73 61 67 65 3a 20 25 73 90 02 07 2f 74 6f 2f 62 65 2f 65 6e 63 90 02 02 79 70 74 65 64 90 00 } //01 00 
		$a_01_1 = {2e 76 6d 64 6b } //01 00 
		$a_01_2 = {2e 76 73 77 70 } //01 00 
		$a_01_3 = {45 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 3a } //01 00 
		$a_01_4 = {53 6b 69 70 70 65 64 20 66 69 6c 65 73 3a } //00 00 
	condition:
		any of ($a_*)
 
}