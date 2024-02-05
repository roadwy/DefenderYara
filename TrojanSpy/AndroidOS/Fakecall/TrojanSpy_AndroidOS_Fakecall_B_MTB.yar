
rule TrojanSpy_AndroidOS_Fakecall_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecall.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 76 69 70 2f 73 79 73 74 65 6d 2f 63 6f 72 65 2f 6e 65 74 2f 65 6e 74 69 74 79 2f 43 61 6c 6c 4c 6f 67 45 6e 74 69 74 79 } //01 00 
		$a_00_1 = {53 6d 73 55 70 6c 6f 61 64 4d 61 6e 61 67 65 72 } //01 00 
		$a_00_2 = {61 33 5f 73 61 6e 77 61 6d 6f 6e 65 79 } //01 00 
		$a_01_3 = {49 4e 43 4f 4d 49 4e 47 5f 43 41 4c 4c 5f 53 54 41 54 45 5f 4f 46 46 48 4f 4f 4b } //01 00 
		$a_00_4 = {61 32 5f 79 75 6a 69 6e 62 61 6e 6b 2e 6d 70 33 } //00 00 
		$a_00_5 = {5d 04 00 } //00 0a 
	condition:
		any of ($a_*)
 
}