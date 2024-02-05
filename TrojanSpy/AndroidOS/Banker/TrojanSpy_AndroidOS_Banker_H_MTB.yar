
rule TrojanSpy_AndroidOS_Banker_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 6c 64 5f 73 74 61 72 74 5f 69 6e 6a 00 } //01 00 
		$a_00_1 = {61 70 70 5f 69 6e 6a 65 63 74 } //01 00 
		$a_00_2 = {2e 4c 6f 67 73 20 63 6f 6d 2e 67 6f 6f 67 6c 65 2e 61 6e 64 72 6f 69 64 2e 61 70 70 73 2e 61 75 74 68 65 6e 74 69 63 61 74 6f 72 32 3a } //01 00 
		$a_00_3 = {7c 7c 79 6f 75 4e 65 65 64 4d 6f 72 65 52 65 73 6f 75 72 63 65 73 7c 7c } //01 00 
		$a_00_4 = {66 69 6e 64 41 63 63 65 73 73 69 62 69 6c 69 74 79 4e 6f 64 65 49 6e 66 6f 73 42 79 56 69 65 77 49 64 } //01 00 
		$a_00_5 = {70 65 72 66 6f 72 6d 47 6c 6f 62 61 6c 41 63 74 69 6f 6e } //00 00 
		$a_00_6 = {5d 04 00 00 } //32 57 
	condition:
		any of ($a_*)
 
}