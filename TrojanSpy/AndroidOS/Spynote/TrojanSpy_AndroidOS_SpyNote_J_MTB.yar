
rule TrojanSpy_AndroidOS_SpyNote_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyNote.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 73 6b 5f 62 61 74 74 61 72 79 } //01 00 
		$a_00_1 = {69 73 45 6d 75 5f 44 49 56 5f 49 44 5f 6c 61 74 6f 72 } //01 00 
		$a_00_2 = {53 63 72 65 65 6e 73 68 6f 74 52 65 73 75 6c 74 } //01 00 
		$a_00_3 = {47 65 74 52 65 71 75 69 65 72 64 50 72 69 6d 73 } //01 00 
		$a_00_4 = {67 65 74 6d 65 74 32 } //00 00 
	condition:
		any of ($a_*)
 
}