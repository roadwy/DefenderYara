
rule TrojanSpy_AndroidOS_SmFrow_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmFrow.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6e 61 72 75 74 6f 2e 74 65 64 2e 75 70 6c 6f 61 64 53 6d 73 } //01 00 
		$a_01_1 = {64 65 6c 65 74 65 20 66 72 6f 6d 20 74 5f 73 6d 73 20 77 68 65 72 65 20 69 64 3d 3f } //01 00 
		$a_01_2 = {73 6d 73 57 61 74 63 68 2e 64 62 } //01 00 
		$a_01_3 = {53 6d 73 55 70 6c 6f 61 64 54 61 73 6b } //01 00 
		$a_01_4 = {73 74 72 69 6e 67 54 6f 47 73 6d 37 42 69 74 50 61 63 6b 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}