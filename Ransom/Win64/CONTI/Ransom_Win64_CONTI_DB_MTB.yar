
rule Ransom_Win64_CONTI_DB_MTB{
	meta:
		description = "Ransom:Win64/CONTI.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 6c 6c 20 6f 66 20 74 68 65 20 64 61 74 61 20 74 68 61 74 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 63 6f 6e 74 69 72 65 63 6f 76 65 72 79 2e 69 6e 66 6f } //01 00 
		$a_81_2 = {63 72 79 70 74 6f 72 5f 64 6c 6c 2e 70 64 62 } //01 00 
		$a_81_3 = {59 4f 55 20 53 48 4f 55 4c 44 20 42 45 20 41 57 41 52 45 21 } //01 00 
		$a_81_4 = {2e 6f 6e 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}