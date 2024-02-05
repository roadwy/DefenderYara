
rule TrojanSpy_AndroidOS_Abarw_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Abarw.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 72 61 62 57 61 72 65 53 4d 53 } //01 00 
		$a_01_1 = {5f 72 65 61 6c 5f 74 69 6d 65 5f 63 68 65 63 6b } //01 00 
		$a_01_2 = {53 61 69 64 48 61 63 6b } //01 00 
		$a_01_3 = {6c 69 73 74 4d 61 70 44 61 74 61 } //01 00 
		$a_01_4 = {73 6d 73 5f 63 68 69 6c 64 5f 6c 69 73 74 65 6e 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}