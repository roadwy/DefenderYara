
rule Ransom_MSIL_CryptoLocker_DC_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {65 72 61 77 6f 73 6e 61 72 2e 65 78 65 } //01 00 
		$a_81_1 = {65 72 61 77 6f 73 6e 61 72 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00 
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_4 = {73 65 74 5f 55 73 65 4d 61 63 68 69 6e 65 4b 65 79 53 74 6f 72 65 } //01 00 
		$a_81_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}