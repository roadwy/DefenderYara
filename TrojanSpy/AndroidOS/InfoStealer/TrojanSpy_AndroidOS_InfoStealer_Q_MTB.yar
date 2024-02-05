
rule TrojanSpy_AndroidOS_InfoStealer_Q_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 50 68 6f 6e 65 2f 43 61 6c 6c 4c 6f 67 } //01 00 
		$a_00_1 = {2f 61 70 69 2f 50 68 6f 6e 65 2f 44 65 6c 41 70 6b } //01 00 
		$a_00_2 = {68 6b 5f 64 61 74 65 } //01 00 
		$a_00_3 = {61 73 79 6e 63 43 61 6c 6c 4f 75 74 } //01 00 
		$a_00_4 = {2f 53 6d 73 49 6e 66 6f 3b } //01 00 
		$a_00_5 = {2f 43 61 6c 6c 49 6e 53 65 72 76 69 63 65 3b } //00 00 
		$a_00_6 = {5d 04 00 00 } //1b 82 
	condition:
		any of ($a_*)
 
}