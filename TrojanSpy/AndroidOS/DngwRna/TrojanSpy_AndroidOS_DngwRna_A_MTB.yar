
rule TrojanSpy_AndroidOS_DngwRna_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/DngwRna.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 61 73 74 53 4d 53 49 6e 62 6f 78 52 65 61 64 54 69 6d 65 } //01 00 
		$a_00_1 = {06 6f 64 72 2e 6f 64 00 } //01 00 
		$a_00_2 = {06 63 6e 67 2e 63 6e 00 } //01 00 
		$a_00_3 = {2d 67 62 77 72 68 74 79 } //01 00 
		$a_00_4 = {2d 73 6d 74 72 74 78 63 62 } //01 00 
		$a_00_5 = {2d 67 63 6d 61 70 63 72 } //00 00 
		$a_00_6 = {5d 04 00 00 } //f2 5f 
	condition:
		any of ($a_*)
 
}