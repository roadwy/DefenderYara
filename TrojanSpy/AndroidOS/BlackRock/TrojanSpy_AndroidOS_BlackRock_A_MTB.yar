
rule TrojanSpy_AndroidOS_BlackRock_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/BlackRock.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 53 74 61 72 74 4b 65 79 4c 6f 67 73 2e 74 78 74 } //01 00 
		$a_01_1 = {2f 53 63 72 65 65 6e 5f 4c 6f 63 6b 2e 74 78 74 } //01 00 
		$a_01_2 = {32 36 6b 6f 7a 51 61 4b 77 52 75 4e 4a 32 34 74 } //01 00 
		$a_01_3 = {4d 7a 56 42 4f 45 55 34 52 55 45 78 4e 7a 64 44 4e 54 41 33 4e 7a 4e 32 64 34 61 61 69 55 32 65 43 46 37 7a 47 70 61 78 47 6e 5a 6f 43 55 73 34 42 79 43 36 33 7a 56 7a 39 6d 48 69 65 51 71 75 } //01 00 
		$a_01_4 = {53 70 61 6d 5f 6f 6e 5f 63 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_5 = {53 74 61 72 74 4b 65 79 4c 6f 67 73 } //00 00 
	condition:
		any of ($a_*)
 
}