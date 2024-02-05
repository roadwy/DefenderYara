
rule TrojanSpy_AndroidOS_Ahmyth_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ahmyth.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 64 65 66 61 75 6c 74 2d 64 69 61 6c 65 72 } //02 00 
		$a_00_1 = {61 48 52 30 63 44 6f 76 4c 7a 45 79 4d 79 34 79 4e 54 4d 75 4d 54 45 77 4c 6a 49 33 } //01 00 
		$a_00_2 = {73 74 61 72 74 52 65 63 6f 72 64 69 6e 67 } //01 00 
		$a_00_3 = {73 6d 73 4c 69 73 74 } //01 00 
		$a_00_4 = {77 71 6c 77 62 6e 30 61 72 73 77 71 6c 77 62 6e 30 2f 6b 6b 64 61 74 61 2e 64 61 74 } //00 00 
		$a_00_5 = {5d 04 00 } //00 9e 
	condition:
		any of ($a_*)
 
}