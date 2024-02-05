
rule TrojanSpy_AndroidOS_SmForw_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 70 5f 73 74 61 74 65 2e 70 68 70 } //01 00 
		$a_00_1 = {69 6e 64 65 78 2e 70 68 70 3f 74 79 70 65 3d 6a 6f 69 6e 26 74 65 6c 6e 75 6d 3d } //01 00 
		$a_00_2 = {73 65 6e 64 55 73 65 72 44 61 74 61 } //01 00 
		$a_00_3 = {68 70 5f 67 65 74 73 6d 73 62 6c 6f 63 6b 73 74 61 74 65 2e 70 68 70 3f 74 65 6c 6e 75 6d 3d } //00 00 
	condition:
		any of ($a_*)
 
}