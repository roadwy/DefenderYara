
rule Ransom_Linux_BlackSuit_A_MTB{
	meta:
		description = "Ransom:Linux/BlackSuit.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 45 41 44 4d 45 2e 42 6c 61 63 6b 53 75 69 74 2e 74 78 74 } //01 00 
		$a_01_1 = {2e 62 6c 61 63 6b 73 75 69 74 5f 6c 6f 67 5f } //01 00 
		$a_01_2 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d 66 6f 72 63 65 20 2d 2d 77 6f 72 6c 64 2d 69 64 } //01 00 
		$a_01_3 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6c 69 73 74 20 3e 20 50 49 44 5f 6c 69 73 74 } //01 00 
		$a_01_4 = {70 73 20 2d 43 63 7c 67 72 65 70 20 76 6d 73 79 73 6c 6f 67 64 20 3e 20 50 53 5f 73 79 73 6c 6f 67 } //00 00 
	condition:
		any of ($a_*)
 
}