
rule TrojanSpy_AndroidOS_InfoStealer_P_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 75 70 64 61 74 65 2f 73 79 73 74 65 6d 2f 69 6d 70 6f 72 74 61 6e 74 2f 63 61 6c 6c 72 65 63 6f 72 64 2f } //01 00 
		$a_00_1 = {2f 77 68 61 74 73 61 70 70 2f 47 65 74 57 68 61 74 73 44 61 74 61 3b } //01 00 
		$a_00_2 = {4d 65 73 73 61 67 65 57 68 61 74 73 4d 6f 64 65 6c } //01 00 
		$a_00_3 = {4d 65 73 73 65 6e 67 65 72 4d 65 73 73 61 67 65 4d 6f 64 65 6c } //01 00 
		$a_00_4 = {53 74 61 72 74 43 6f 6d 6d 61 6e 64 46 72 6f 6d 6f 6e 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //01 00 
		$a_00_5 = {6c 6f 61 64 41 6c 6c 42 79 44 61 74 65 41 6e 64 43 6f 6e 76 65 72 73 61 74 69 6f 6e } //00 00 
		$a_00_6 = {5d 04 00 00 } //79 80 
	condition:
		any of ($a_*)
 
}