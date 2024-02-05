
rule TrojanSpy_AndroidOS_Ewalls_T_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ewalls.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {61 70 69 2e 62 69 74 2e 6c 79 2f 73 68 6f 72 74 65 6e 3f 76 65 72 73 69 6f 6e 3d 90 02 06 26 6c 6f 67 69 6e 3d 65 77 61 6c 6c 70 61 70 65 72 26 61 70 69 4b 65 79 3d 90 02 35 26 6c 6f 6e 67 55 72 6c 90 00 } //01 00 
		$a_00_1 = {73 65 6e 64 44 65 76 69 63 65 49 6e 66 6f 73 } //01 00 
		$a_00_2 = {2f 61 70 69 2f 77 61 6c 6c 70 61 70 65 72 73 2f 6c 6f 67 2f 61 63 74 69 6f 6e 5f 6c 6f 67 3f 74 79 70 65 65 } //01 00 
		$a_00_3 = {79 73 6c 65 72 2e 63 6f 6d } //01 00 
		$a_00_4 = {61 70 70 73 63 6f 6c 6f 72 2e 6e 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}