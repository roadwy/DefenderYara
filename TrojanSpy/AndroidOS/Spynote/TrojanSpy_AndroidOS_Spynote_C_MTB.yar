
rule TrojanSpy_AndroidOS_Spynote_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6d 66 30 2f 63 33 62 35 62 6d 39 30 7a 71 2f 70 61 74 63 68 } //01 00 
		$a_01_1 = {73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 20 2d 70 20 2f 73 64 63 61 72 64 2f 72 6f 6f 74 53 55 } //01 00 
		$a_00_2 = {72 6f 6f 74 40 } //01 00 
		$a_00_3 = {2f 62 61 73 65 2e 61 70 6b } //01 00 
		$a_00_4 = {68 61 73 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 21 3d 30 20 41 4e 44 20 28 6d 69 6d 65 74 79 70 65 3d 3f 20 4f 52 20 6d 69 6d 65 74 79 70 65 3d 3f 29 } //00 00 
	condition:
		any of ($a_*)
 
}