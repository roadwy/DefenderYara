
rule Ransom_MSIL_Cryptolocker_PDG_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //01 00 
		$a_81_2 = {45 6e 63 72 79 70 74 46 69 6c 65 } //01 00 
		$a_81_3 = {41 45 53 5f 45 6e 63 72 79 70 74 } //01 00 
		$a_81_4 = {5a 65 72 30 42 79 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDG_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {2e 6c 6f 63 6b 65 64 } //01 00 
		$a_81_2 = {45 6e 63 72 79 70 74 46 69 6c 65 } //01 00 
		$a_81_3 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //01 00 
		$a_81_4 = {62 6c 6f 63 6b 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDG_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6e 6e 61 62 65 6c 6c 65 2e 65 78 65 } //01 00 
		$a_81_1 = {41 63 74 69 6f 6e 45 6e 63 72 79 70 74 } //01 00 
		$a_81_2 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //01 00 
		$a_81_3 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } //01 00 
		$a_81_4 = {47 65 74 46 69 6c 65 73 } //01 00 
		$a_81_5 = {43 46 41 4c 20 48 61 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}