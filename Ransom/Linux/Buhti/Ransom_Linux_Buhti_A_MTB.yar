
rule Ransom_Linux_Buhti_A_MTB{
	meta:
		description = "Ransom:Linux/Buhti.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 5f 66 69 6c 65 } //01 00 
		$a_01_1 = {62 75 68 74 69 52 61 6e 73 6f 6d } //01 00 
		$a_01_2 = {66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_01_3 = {72 65 73 74 6f 72 65 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}