
rule Ransom_Linux_RedAlert_A{
	meta:
		description = "Ransom:Linux/RedAlert.A,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 75 6e 20 63 6f 6d 6d 61 6e 64 20 66 6f 72 20 73 74 6f 70 20 61 6c 6c 20 72 75 6e 6e 69 6e 67 20 56 4d } //01 00 
		$a_00_1 = {46 69 6c 65 20 66 6f 72 20 65 6e 63 72 79 70 74 } //01 00 
		$a_00_2 = {2e 76 6d 64 6b } //01 00 
		$a_00_3 = {5b 20 4e 31 33 56 20 5d } //01 00 
		$a_00_4 = {68 77 6e 72 74 78 70 3a 66 3a } //00 00 
		$a_00_5 = {5d 04 00 00 } //49 39 
	condition:
		any of ($a_*)
 
}