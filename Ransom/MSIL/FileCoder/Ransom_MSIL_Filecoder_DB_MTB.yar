
rule Ransom_MSIL_Filecoder_DB_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 64 65 63 72 79 70 74 65 64 20 6e 6f 77 } //01 00 
		$a_81_1 = {2e 50 41 54 50 41 54 } //01 00 
		$a_81_2 = {68 65 61 64 70 61 74 73 20 74 6f 20 67 6f 21 } //01 00 
		$a_81_3 = {70 61 74 70 61 74 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_DB_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //01 00 
		$a_81_1 = {53 74 69 6c 6c 20 6c 6f 63 6b 65 64 2e 20 4a 75 73 74 20 70 61 79 2e } //01 00 
		$a_81_2 = {55 6e 6c 6f 63 6b 65 64 2e 20 54 68 61 6e 6b 73 20 66 6f 72 20 70 61 79 69 6e 67 2e } //01 00 
		$a_81_3 = {50 34 59 4d 45 } //01 00 
		$a_81_4 = {70 61 73 73 77 6f 72 64 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_DB_MTB_3{
	meta:
		description = "Ransom:MSIL/Filecoder.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {4f 6f 70 73 2c 79 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //01 00 
		$a_81_1 = {53 65 6e 64 20 24 33 30 30 20 77 6f 72 74 68 20 6f 66 20 62 69 74 63 6f 69 6e 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 3a } //01 00 
		$a_81_2 = {2e 6c 6f 63 6b 65 64 } //01 00 
		$a_81_3 = {4d 41 4c 57 41 52 45 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_DB_MTB_4{
	meta:
		description = "Ransom:MSIL/Filecoder.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 65 72 2e 70 64 62 } //01 00 
		$a_81_1 = {2e 6c 6f 63 6b 65 64 } //01 00 
		$a_81_2 = {5c 64 37 38 62 36 66 33 30 32 32 35 63 64 63 38 31 31 61 64 66 65 38 64 34 65 37 63 39 66 64 33 34 5c 45 6e 63 72 79 70 74 65 72 2e 65 78 65 } //01 00 
		$a_81_3 = {5c 64 37 38 62 36 66 33 30 32 32 35 63 64 63 38 31 31 61 64 66 65 38 64 34 65 37 63 39 66 64 33 34 5c 44 65 63 72 79 70 74 65 72 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}