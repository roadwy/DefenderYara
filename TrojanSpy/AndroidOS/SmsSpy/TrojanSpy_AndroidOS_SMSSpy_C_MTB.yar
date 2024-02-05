
rule TrojanSpy_AndroidOS_SMSSpy_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6e 73 74 5f 72 65 67 69 73 74 65 72 5f 62 6f 74 } //01 00 
		$a_00_1 = {73 65 74 53 61 76 65 49 6e 62 6f 78 53 6d 73 } //01 00 
		$a_00_2 = {43 6f 6d 61 6e 64 20 73 65 6e 64 20 73 6d 73 20 69 64 } //01 00 
		$a_00_3 = {73 6d 73 43 6f 6e 74 72 6f 6c } //01 00 
		$a_00_4 = {53 65 74 20 62 6f 74 20 69 64 } //01 00 
		$a_00_5 = {73 61 76 65 43 61 72 64 20 2d 20 67 65 74 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}