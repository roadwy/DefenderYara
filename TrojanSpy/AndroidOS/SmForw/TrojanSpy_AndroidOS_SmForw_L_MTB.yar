
rule TrojanSpy_AndroidOS_SmForw_L_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4d 53 5f 42 6c 6f 63 6b 53 74 61 74 65 } //01 00 
		$a_01_1 = {49 6e 73 65 72 74 43 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_2 = {61 6e 73 77 65 72 52 69 6e 67 69 6e 67 43 61 6c 6c } //01 00 
		$a_01_3 = {68 70 5f 67 65 74 73 6d 73 62 6c 6f 63 6b 73 74 61 74 65 2e 70 68 70 } //01 00 
		$a_01_4 = {69 6e 64 65 78 2e 70 68 70 3f 74 79 70 65 3d 72 65 63 65 69 76 65 73 6d 73 26 74 65 6c 6e 75 6d 3d } //00 00 
	condition:
		any of ($a_*)
 
}