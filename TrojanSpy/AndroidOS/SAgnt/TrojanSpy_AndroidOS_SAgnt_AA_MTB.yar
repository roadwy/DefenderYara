
rule TrojanSpy_AndroidOS_SAgnt_AA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 74 72 61 5f 73 6d 73 5f 6e 6f } //01 00 
		$a_01_1 = {74 74 70 73 3a 2f 2f 77 77 77 2e 73 6e 65 74 61 70 69 73 2e 63 6f 6d 2f 61 70 69 2f } //01 00 
		$a_01_2 = {73 6d 73 2d 74 65 73 74 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 } //01 00 
		$a_01_3 = {74 68 69 73 5f 73 6d 73 5f 72 65 63 65 69 76 65 72 5f 61 70 70 } //01 00 
		$a_01_4 = {75 70 6c 6f 61 64 55 73 65 72 } //01 00 
		$a_01_5 = {69 73 44 6f 6e 65 50 65 72 6d 69 73 73 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}