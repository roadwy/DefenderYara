
rule TrojanSpy_AndroidOS_CallerSpy_A{
	meta:
		description = "TrojanSpy:AndroidOS/CallerSpy.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 70 64 61 74 65 43 61 6c 6c 4c 6f 67 73 4c 69 73 74 } //01 00 
		$a_00_1 = {73 79 6e 63 5f 64 61 74 61 5f 6c 6f 63 61 6c 6c 79 } //01 00 
		$a_00_2 = {75 70 6c 6f 61 64 45 6e 76 69 6f 72 6d 65 6e 74 52 65 63 6f 72 64 69 6e 67 73 } //01 00 
		$a_00_3 = {75 70 64 61 74 65 43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 73 } //00 00 
		$a_00_4 = {5d 04 00 } //00 9e 
	condition:
		any of ($a_*)
 
}