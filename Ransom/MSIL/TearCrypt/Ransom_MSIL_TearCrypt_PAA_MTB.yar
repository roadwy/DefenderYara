
rule Ransom_MSIL_TearCrypt_PAA_MTB{
	meta:
		description = "Ransom:MSIL/TearCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 65 61 72 64 72 6f 70 2e 70 64 62 } //01 00 
		$a_01_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 61 6e 61 67 65 72 } //01 00 
		$a_01_2 = {6b 6f 6d 70 75 74 65 72 20 6d 61 20 76 69 72 75 73 61 2d 20 6b 74 } //01 00 
		$a_01_3 = {3c 70 3e 68 61 63 6b 74 68 65 64 65 76 2f 74 65 61 72 64 72 6f 70 3c 2f 70 3e } //01 00 
		$a_81_4 = {74 65 61 72 64 72 6f 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}