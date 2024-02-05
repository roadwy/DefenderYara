
rule Ransom_MSIL_Cryptolocker_PDH_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {5a 69 67 67 79 20 52 61 6e 73 6f 6d 77 61 72 65 } //01 00 
		$a_81_1 = {52 65 61 6d 61 69 6e 69 6e 67 20 74 69 6d 65 3a } //01 00 
		$a_81_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 44 69 73 6b 44 72 69 76 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDH_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {52 61 6e 73 6f 6d 65 54 6f 61 64 } //01 00 
		$a_81_2 = {50 6f 76 6c 73 6f 6d 77 61 72 65 } //01 00 
		$a_81_3 = {44 65 63 72 79 70 74 20 46 69 6c 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDH_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 53 20 45 6e 63 72 79 70 74 65 72 } //01 00 
		$a_81_1 = {75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 } //01 00 
		$a_81_2 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDH_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 66 69 6c 65 73 20 64 65 6c 65 74 65 64 } //01 00 
		$a_81_1 = {59 6f 75 72 20 46 69 6c 65 73 20 77 65 72 65 20 64 65 6c 65 74 65 64 } //01 00 
		$a_81_2 = {63 72 79 70 74 5f 65 6e 67 69 6e 65 } //01 00 
		$a_81_3 = {65 6e 63 72 79 70 74 65 64 5f 73 6f 75 6e 64 2e 77 61 76 } //01 00 
		$a_81_4 = {2e 63 72 79 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDH_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 28 63 6f 75 6e 74 3a 20 6e 29 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 } //01 00 
		$a_81_2 = {65 6e 63 72 79 70 74 65 64 46 69 6c 65 43 6f 75 6e 74 } //01 00 
		$a_81_3 = {46 69 6c 65 45 6e 63 72 79 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}