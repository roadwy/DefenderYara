
rule TrojanSpy_AndroidOS_Campys_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Campys.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 2d 66 69 6c 65 2e 70 68 70 } //01 00 
		$a_01_1 = {67 65 74 2d 66 75 6e 63 74 69 6f 6e 2e 70 68 70 } //01 00 
		$a_01_2 = {61 6d 73 65 72 76 69 63 65 3a 73 65 74 75 70 6c 6f 67 67 69 6e 67 } //01 00 
		$a_00_3 = {72 65 63 6f 72 64 63 61 6c 6c } //01 00 
		$a_00_4 = {61 6c 6c 73 6d 73 } //01 00 
		$a_01_5 = {61 6e 73 77 65 72 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}