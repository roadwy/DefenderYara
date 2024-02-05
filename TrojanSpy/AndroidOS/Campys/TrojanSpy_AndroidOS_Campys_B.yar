
rule TrojanSpy_AndroidOS_Campys_B{
	meta:
		description = "TrojanSpy:AndroidOS/Campys.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 6d 53 65 72 76 69 63 65 3a 73 65 74 75 70 4c 6f 67 67 69 6e 67 } //01 00 
		$a_00_1 = {44 65 6c 65 74 65 20 53 4d 53 20 73 75 63 63 65 73 73 } //01 00 
		$a_00_2 = {43 61 6c 6c 20 72 65 63 6f 72 64 20 73 74 61 72 74 20 66 6f 72 20 3a } //01 00 
		$a_00_3 = {2f 75 70 6c 6f 61 64 2d 6c 6f 67 2e 70 68 70 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}