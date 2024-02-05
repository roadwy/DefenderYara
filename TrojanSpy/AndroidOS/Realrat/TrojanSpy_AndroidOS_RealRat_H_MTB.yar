
rule TrojanSpy_AndroidOS_RealRat_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RealRat.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 70 69 78 6f 2f 72 61 74 2f 6d 61 69 6e } //01 00 
		$a_00_1 = {4c 63 6f 6d 2f 72 65 7a 61 2f 73 68 2f 64 65 76 69 63 65 69 6e 66 6f } //01 00 
		$a_00_2 = {35 2e 32 35 35 2e 31 31 37 2e 31 31 35 } //01 00 
		$a_00_3 = {50 4e 55 70 6c 6f 61 64 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_RealRat_H_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/RealRat.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,2a 00 2a 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {69 72 2e 4d 72 41 76 65 6e 74 65 72 2e 69 70 74 76 } //0a 00 
		$a_01_1 = {74 61 72 67 65 74 61 64 64 72 65 73 73 } //0a 00 
		$a_01_2 = {68 69 64 65 41 70 70 49 63 6f 6e } //0a 00 
		$a_01_3 = {7e 74 65 73 74 2e 74 65 73 74 } //0a 00 
		$a_01_4 = {50 4e 53 4d 53 } //0a 00 
		$a_01_5 = {69 73 52 75 6e 6e 69 6e 67 4f 6e 45 6d 75 6c 61 74 6f 72 } //01 00 
		$a_01_6 = {61 6c 6c 5f 73 6d 73 } //01 00 
		$a_01_7 = {61 70 70 5f 6c 69 73 74 } //01 00 
		$a_01_8 = {68 69 64 65 5f 61 6c 6c } //00 00 
		$a_00_9 = {5d 04 00 00 41 3e 05 80 5c 27 00 00 47 3e 05 80 00 00 01 00 08 00 11 00 af 01 4c 6f 6b 69 42 } //6f 74 
	condition:
		any of ($a_*)
 
}