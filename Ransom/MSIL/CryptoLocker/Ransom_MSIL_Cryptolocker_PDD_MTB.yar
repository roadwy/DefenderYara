
rule Ransom_MSIL_Cryptolocker_PDD_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {62 69 72 62 77 61 72 65 } //01 00 
		$a_81_1 = {2e 62 69 72 62 62 } //01 00 
		$a_81_2 = {72 61 6e 73 6f 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_3 = {44 65 63 72 79 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDD_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 75 63 63 65 73 73 20 44 65 63 72 79 70 74 } //01 00 
		$a_81_1 = {42 61 64 64 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_2 = {2e 62 61 64 64 79 } //01 00 
		$a_81_3 = {57 72 6f 6e 67 2e 48 61 68 61 68 61 2e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDD_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 72 61 70 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00 
		$a_81_1 = {51 33 4a 68 63 48 4e 76 62 58 64 68 63 6d 55 6b } //01 00 
		$a_81_2 = {47 65 74 46 69 6c 65 73 } //01 00 
		$a_81_3 = {45 6e 63 72 79 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDD_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 72 79 70 74 6f 6c 6f 63 6b 65 72 } //01 00 
		$a_81_1 = {62 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 } //01 00 
		$a_81_2 = {4b 45 59 2e 63 72 79 70 74 6f 6c 6f 63 6b 65 72 } //01 00 
		$a_81_3 = {52 65 63 6f 76 65 72 79 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDD_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 69 6e 67 20 79 6f 75 72 20 66 69 6c 65 73 } //01 00 
		$a_81_1 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //01 00 
		$a_81_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00 
		$a_81_3 = {2e 57 65 53 74 20 4e 65 74 20 46 61 6b 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDD_MTB_6{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 41 72 65 20 73 61 66 65 6c 79 20 45 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //01 00 
		$a_81_2 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //01 00 
		$a_81_3 = {2e 6f 6e 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDD_MTB_7{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {50 75 72 63 68 61 73 65 20 42 69 74 63 6f 69 6e } //01 00 
		$a_81_2 = {44 65 63 72 79 70 74 69 6f 6e 20 4b 65 79 } //01 00 
		$a_81_3 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 61 6c 6c 20 6e 6f 77 20 64 65 63 72 79 70 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Cryptolocker_PDD_MTB_8{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 69 6f 6e 20 50 72 6f 67 72 61 6d 20 66 6f 72 20 43 72 79 70 74 6f 6c 6f 63 6b 65 72 } //01 00 
		$a_81_1 = {63 72 79 70 74 6f 6c 6f 63 6b 65 72 2e 65 78 65 } //01 00 
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00 
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_4 = {44 65 62 75 67 67 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}