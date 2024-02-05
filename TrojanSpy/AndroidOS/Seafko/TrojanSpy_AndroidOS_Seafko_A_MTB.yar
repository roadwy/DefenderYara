
rule TrojanSpy_AndroidOS_Seafko_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Seafko.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 73 61 73 2f 73 65 61 66 6b 6f 61 67 65 6e 74 2f 73 65 61 66 6b 6f 61 67 65 6e 74 } //01 00 
		$a_01_1 = {63 6f 6e 74 65 6e 74 3a 2f 2f 63 61 6c 6c 5f 6c 6f 67 2f 63 61 6c 6c 73 } //01 00 
		$a_01_2 = {54 65 72 6d 69 6e 61 74 69 6e 67 20 61 6c 6c 20 41 67 65 6e 74 20 73 65 72 76 69 63 65 73 } //01 00 
		$a_00_3 = {53 45 41 46 4b 4f 20 41 54 54 41 43 4b 20 53 59 53 54 45 4d 20 49 53 20 49 4e 20 43 4f 4e 54 52 4f 4c } //00 00 
		$a_00_4 = {5d 04 00 } //00 01 
	condition:
		any of ($a_*)
 
}