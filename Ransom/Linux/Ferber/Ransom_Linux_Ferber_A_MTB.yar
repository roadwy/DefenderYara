
rule Ransom_Linux_Ferber_A_MTB{
	meta:
		description = "Ransom:Linux/Ferber.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 78 78 78 78 2e 6f 6e 69 6f 6e 2f } //01 00 
		$a_00_1 = {52 45 43 4f 56 45 52 59 5f 52 45 41 44 4d 45 } //01 00 
		$a_00_2 = {44 65 63 6f 64 69 6e 67 4c 6f 6f 6b 75 70 41 72 72 61 79 } //01 00 
		$a_00_3 = {3a 2f 2f 70 69 67 65 74 72 7a 6c 70 65 72 6a 72 65 79 72 33 66 62 79 74 6d 32 37 62 6c 6a 61 71 34 65 75 6e 67 76 33 67 64 71 32 74 6f 68 6e 6f 79 66 72 71 75 34 62 78 35 71 64 2e 6f 6e 69 6f 6e 2f 62 74 } //00 00 
	condition:
		any of ($a_*)
 
}