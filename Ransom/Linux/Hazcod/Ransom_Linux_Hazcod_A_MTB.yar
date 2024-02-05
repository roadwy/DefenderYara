
rule Ransom_Linux_Hazcod_A_MTB{
	meta:
		description = "Ransom:Linux/Hazcod.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 68 61 7a 63 6f 64 2f 72 61 6e 73 6f 6d 77 68 65 72 65 } //01 00 
		$a_00_1 = {2e 63 72 79 70 74 65 64 } //01 00 
		$a_00_2 = {76 69 63 74 69 6d 53 69 7a 65 } //01 00 
		$a_00_3 = {64 69 72 74 79 4c 6f 63 6b 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}