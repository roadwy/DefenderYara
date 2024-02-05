
rule Ransom_MSIL_CryptoLocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //01 00 
		$a_81_1 = {42 69 74 63 6f 69 6e } //01 00 
		$a_81_2 = {2e 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_3 = {72 61 6e 73 6f 6d 77 61 72 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_CryptoLocker_DA_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00 
		$a_81_2 = {64 65 73 6b 74 6f 70 2e 69 6e 69 } //01 00 
		$a_81_3 = {50 61 73 73 77 6f 72 64 } //01 00 
		$a_81_4 = {31 32 33 34 35 36 } //00 00 
	condition:
		any of ($a_*)
 
}