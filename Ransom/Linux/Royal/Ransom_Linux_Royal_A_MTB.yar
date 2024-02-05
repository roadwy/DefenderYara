
rule Ransom_Linux_Royal_A_MTB{
	meta:
		description = "Ransom:Linux/Royal.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d 68 61 72 64 20 2d 2d 77 6f 72 6c 64 2d 69 64 } //01 00 
		$a_01_1 = {2e 72 6f 79 61 6c 5f 77 } //01 00 
		$a_01_2 = {72 6f 79 61 6c 5f 6c 6f 67 5f } //01 00 
		$a_01_3 = {2f 72 65 61 64 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}