
rule TrojanSpy_AndroidOS_Nickispy_A{
	meta:
		description = "TrojanSpy:AndroidOS/Nickispy.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6e 69 63 6b 79 2f 6c 79 79 77 73 2f 78 6d 61 6c 6c } //01 00 
		$a_01_1 = {6a 69 6e 2e 35 36 6d 6f 2e 63 6f 6d } //01 00 
		$a_01_2 = {2f 73 64 63 61 72 64 2f 73 68 61 6e 67 7a 68 6f 75 2f 63 61 6c 6c 72 65 63 6f 72 64 2f } //01 00 
		$a_01_3 = {58 4d 5f 53 6d 73 4c 69 73 74 65 6e 65 72 24 53 6d 73 43 6f 6e 74 65 6e 74 } //01 00 
		$a_01_4 = {58 4d 5f 43 61 6c 6c 52 65 63 6f 72 64 53 65 72 76 69 63 65 24 54 65 6c 65 4c 69 73 74 65 6e 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}