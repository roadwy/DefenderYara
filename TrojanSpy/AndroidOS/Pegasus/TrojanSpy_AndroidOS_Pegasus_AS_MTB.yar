
rule TrojanSpy_AndroidOS_Pegasus_AS_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Pegasus.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 65 67 61 73 75 73 20 6b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 } //01 00 
		$a_00_1 = {64 65 6c 65 74 65 53 6d 73 2d } //01 00 
		$a_00_2 = {2f 64 61 74 61 62 61 73 65 73 2f 6d 6d 73 73 6d 73 2e 64 62 } //01 00 
		$a_00_3 = {73 6d 73 20 6d 6f 6e 69 74 6f 72 } //01 00 
		$a_00_4 = {66 72 69 65 6e 64 73 2e 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //01 00 
		$a_00_5 = {53 4d 53 5f 4c 4f 43 5f 4d 4f 4e } //00 00 
		$a_00_6 = {5d 04 00 00 } //07 8e 
	condition:
		any of ($a_*)
 
}