
rule TrojanSpy_AndroidOS_InfoStealer_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 73 79 73 2f 70 6f 77 65 72 2f 73 79 73 2f 49 6e 63 6f 6d 69 6e 67 53 6d 73 3b } //01 00 
		$a_00_1 = {4c 73 79 73 2f 70 6f 77 65 72 2f 73 79 73 2f 41 75 74 6f 53 74 61 72 74 55 70 3b } //01 00 
		$a_00_2 = {0c 6f 64 4e 6f 74 69 63 65 2e 74 78 74 } //01 00 
		$a_00_3 = {63 6f 6e 74 65 6e 74 3a 2f 2f 62 72 6f 77 73 65 72 2f 62 6f 6f 6b 6d 61 72 6b 73 } //01 00 
		$a_00_4 = {2f 70 75 62 6c 69 63 2f 72 65 63 6f 6f 72 64 69 6e 67 2e 77 61 76 } //00 00 
		$a_00_5 = {5d 04 00 00 } //64 60 
	condition:
		any of ($a_*)
 
}