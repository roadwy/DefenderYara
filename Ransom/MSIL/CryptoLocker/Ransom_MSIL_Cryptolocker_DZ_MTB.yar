
rule Ransom_MSIL_Cryptolocker_DZ_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {55 6e 6c 6f 63 6b 20 59 6f 75 72 20 46 69 6c 65 73 } //01 00 
		$a_81_1 = {5f 45 6e 63 72 79 70 74 65 64 24 } //01 00 
		$a_81_2 = {56 57 35 73 62 32 4e 72 57 57 39 31 63 6b 5a 70 62 47 56 7a 4a 51 } //01 00 
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_4 = {44 65 63 72 79 70 74 41 6c 6c 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}