
rule TrojanSpy_AndroidOS_SpyAgent_DB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.DB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {77 64 73 79 6e 63 65 72 5f 63 6f 6e 66 69 67 5f 64 61 74 61 42 61 73 65 } //01 00 
		$a_00_1 = {73 65 74 44 65 66 4d 73 67 } //01 00 
		$a_00_2 = {72 65 63 2d } //01 00 
		$a_00_3 = {73 65 6e 74 46 69 6c 65 } //01 00 
		$a_00_4 = {75 70 6c 6f 61 64 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}