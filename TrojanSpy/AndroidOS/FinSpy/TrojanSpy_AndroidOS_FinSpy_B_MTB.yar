
rule TrojanSpy_AndroidOS_FinSpy_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FinSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 6d 61 6c 61 73 69 2e 63 6e 2f 4e 6f 55 73 65 56 65 72 73 69 6f 6e 2e 74 78 74 } //01 00 
		$a_01_1 = {67 65 74 43 61 72 64 4e 75 6d 62 65 72 } //01 00 
		$a_01_2 = {63 6f 6d 2e 76 69 70 69 6f 73 } //01 00 
		$a_01_3 = {41 6e 79 75 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_4 = {67 65 74 53 68 6f 75 6a 69 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}