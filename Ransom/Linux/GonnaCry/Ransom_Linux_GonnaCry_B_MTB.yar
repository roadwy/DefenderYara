
rule Ransom_Linux_GonnaCry_B_MTB{
	meta:
		description = "Ransom:Linux/GonnaCry.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 6f 6e 61 20 74 6f 20 64 65 6c 65 74 65 20 66 69 6c 65 20 25 73 } //01 00 
		$a_00_1 = {72 73 61 5f 63 72 70 74 2e 63 } //01 00 
		$a_00_2 = {2f 74 6d 70 2f 47 4e 4e 43 52 59 5f 52 65 61 64 6d 65 2e 74 78 74 21 } //01 00 
		$a_00_3 = {77 65 20 68 61 76 65 20 64 6f 6e 65 20 65 6e 63 72 79 70 74 21 } //01 00 
		$a_00_4 = {64 65 63 72 79 70 74 20 61 6c 6c 20 66 69 6c 65 20 2c 73 73 69 64 3a 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}