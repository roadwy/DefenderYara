
rule TrojanSpy_AndroidOS_PJobRat_C{
	meta:
		description = "TrojanSpy:AndroidOS/PJobRat.C,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 67 6e 6c 69 74 65 } //01 00 
		$a_00_1 = {44 42 5f 52 45 46 5f 4c 53 5f 50 52 4f 54 45 43 54 49 4f 4e } //01 00 
		$a_00_2 = {42 43 41 70 70 73 44 65 74 61 69 6c } //01 00 
		$a_00_3 = {6d 6c 6f 63 6f 74 62 6c } //01 00 
		$a_00_4 = {73 68 6c 63 6d 64 5f } //01 00 
		$a_00_5 = {73 70 5f 6b 65 79 5f 75 73 65 72 6e 61 6d 65 } //00 00 
		$a_00_6 = {5d 04 00 } //00 f3 
	condition:
		any of ($a_*)
 
}