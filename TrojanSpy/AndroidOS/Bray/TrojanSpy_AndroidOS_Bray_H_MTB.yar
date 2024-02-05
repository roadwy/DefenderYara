
rule TrojanSpy_AndroidOS_Bray_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Bray.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {35 03 14 00 34 14 03 00 12 04 48 05 07 03 6e 20 90 01 02 48 00 0a 06 b7 65 8d 55 4f 05 07 03 d8 03 03 01 d8 04 04 01 28 ed 90 00 } //01 00 
		$a_01_1 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //01 00 
		$a_01_2 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_AndroidOS_Bray_H_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Bray.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 69 6e 64 65 78 2f 61 70 69 2f 75 70 6c 6f 61 64 53 6d 73 } //01 00 
		$a_01_1 = {2f 69 6e 64 65 78 2f 61 70 69 2f 71 75 65 72 79 49 73 42 6c 61 63 6b 4c 69 73 74 3f 70 68 6f 6e 65 3d } //01 00 
		$a_01_2 = {2f 69 6e 64 65 78 2f 61 70 69 2f 67 65 74 53 6d 73 4c 69 73 74 3f 64 72 69 76 65 5f 69 64 3d } //01 00 
		$a_01_3 = {2f 69 6e 64 65 78 2f 61 70 69 2f 69 6e 69 74 44 72 69 76 65 } //01 00 
		$a_01_4 = {64 65 6c 65 74 65 43 61 6c 6c 4c 6f 67 } //01 00 
		$a_01_5 = {67 65 74 53 6d 73 46 72 6f 6d 50 68 6f 6e 65 } //00 00 
	condition:
		any of ($a_*)
 
}