
rule TrojanSpy_AndroidOS_Asacub_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Asacub.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,21 00 21 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 61 64 6f 62 65 2f 73 73 6c 70 61 74 68 2f 41 63 74 69 76 69 74 79 42 6c 61 6e 6b } //0a 00 
		$a_01_1 = {2f 73 73 6c 5f 74 6d 70 2f } //0a 00 
		$a_03_2 = {64 61 69 6d 6f 69 64 6f 6d 61 69 6e 65 6d 6e 65 2e 69 6e 66 6f 2f 90 02 30 2f 69 6e 64 65 78 2e 70 68 70 90 00 } //01 00 
		$a_01_3 = {47 50 53 5f 74 72 61 63 6b 5f 63 75 72 72 65 6e 74 } //01 00 
		$a_01_4 = {67 65 74 5f 6c 69 73 74 61 70 70 } //01 00 
		$a_01_5 = {67 65 74 5f 61 6c 6c 73 6d 73 } //01 00 
		$a_01_6 = {67 65 74 5f 68 69 73 74 6f 72 79 } //01 00 
		$a_01_7 = {67 65 74 5f 63 6f 6e 74 61 63 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}