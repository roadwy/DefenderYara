
rule Ransom_MSIL_CryptoLocker_DF_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00 
		$a_81_1 = {41 6c 6f 20 4d 69 6e 65 67 61 6d 65 73 20 72 61 6e 73 6f 6d 77 61 72 65 } //01 00 
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00 
		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_CryptoLocker_DF_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 05 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 74 65 64 } //05 00 
		$a_81_1 = {52 61 6e 73 6f 6d 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //05 00 
		$a_81_2 = {50 6f 76 6c 73 6f 6d 77 61 72 65 } //01 00 
		$a_81_3 = {52 65 61 64 6d 65 46 6f 72 44 65 63 72 79 70 74 69 6f 6e } //01 00 
		$a_81_4 = {50 65 6e 5f 65 74 72 5f 61 74 65 5f 46 69 72 5f 65 77 61 5f 6c 6c } //01 00 
		$a_81_5 = {65 6e 63 72 79 70 74 65 64 46 69 6c 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}