
rule Ransom_MSIL_Filecoder_DD_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 } //01 00 
		$a_81_1 = {75 73 65 72 50 72 69 76 61 74 65 49 64 4b 65 79 2e 74 78 74 } //01 00 
		$a_81_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00 
		$a_81_3 = {42 69 74 63 6f 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_DD_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {55 6e 6c 75 63 6b 79 57 61 72 65 2e 65 78 65 } //01 00 
		$a_81_1 = {42 79 74 65 6c 6f 63 6b 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00 
		$a_81_2 = {45 6e 63 72 79 70 74 65 64 46 69 6c 65 73 4c 69 73 74 } //01 00 
		$a_81_3 = {56 57 35 73 64 57 4e 72 65 56 64 68 63 6d 55 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_DD_MTB_3{
	meta:
		description = "Ransom:MSIL/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {40 52 45 41 44 5f 4d 45 40 2e 74 78 74 } //01 00 
		$a_81_1 = {48 65 6c 6c 6f 20 2c 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 67 65 74 20 65 6e 63 72 79 70 74 65 64 20 21 } //01 00 
		$a_81_2 = {72 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //01 00 
		$a_81_3 = {77 61 6c 2e 62 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_DD_MTB_4{
	meta:
		description = "Ransom:MSIL/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 4f 57 5f 54 4f 5f 44 45 43 59 50 48 45 52 5f 46 49 4c 45 53 } //01 00 
		$a_81_1 = {2e 6c 6f 63 6b 65 64 } //01 00 
		$a_81_2 = {52 47 56 73 5a 58 52 6c 49 46 4e 6f 59 57 52 76 64 33 4d 67 4c 32 46 73 62 43 41 76 63 58 56 70 5a 58 51 } //01 00 
		$a_81_3 = {63 33 52 76 63 43 44 69 67 4a 78 54 62 33 42 6f 62 33 4d 67 51 58 56 30 62 31 56 77 5a 47 46 30 5a 53 42 54 5a 58 4a 32 61 57 4e 6c 34 6f 43 64 49 43 39 35 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_DD_MTB_5{
	meta:
		description = "Ransom:MSIL/Filecoder.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {52 61 6e 73 6f 6d 77 61 72 65 20 44 65 6d 6f 6e 73 74 72 61 74 69 6f 6e 2e 65 78 65 } //01 00 
		$a_81_2 = {52 61 6e 73 6f 6d 77 61 72 65 44 65 6d 6f 6e 73 74 72 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00 
		$a_81_3 = {54 68 69 73 20 69 73 20 61 20 64 65 6d 6f 6e 73 74 72 61 74 69 6f 6e 20 6f 66 20 72 61 6e 73 6f 6d 77 61 72 65 20 61 70 70 6c 69 63 61 74 69 6f 6e 73 2e 20 44 6f 20 6e 6f 74 20 75 73 65 20 75 6e 65 74 68 69 63 61 6c } //00 00 
	condition:
		any of ($a_*)
 
}