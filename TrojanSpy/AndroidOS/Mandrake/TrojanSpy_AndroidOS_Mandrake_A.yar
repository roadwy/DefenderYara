
rule TrojanSpy_AndroidOS_Mandrake_A{
	meta:
		description = "TrojanSpy:AndroidOS/Mandrake.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 66 69 72 6d 77 61 72 65 2f 73 65 72 76 69 63 65 2f 4d 61 69 6e 53 65 72 76 69 63 65 3b } //02 00 
		$a_00_1 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 66 69 72 6d 77 61 72 65 2f 72 65 63 65 69 76 65 72 2f } //02 00 
		$a_00_2 = {70 72 65 66 5f 6b 65 79 5f 61 75 70 5f 73 65 65 6e } //01 00 
		$a_00_3 = {70 72 65 66 5f 6b 65 79 5f 64 65 66 5f 61 73 67 5f 6d 73 67 } //01 00 
		$a_00_4 = {70 72 65 66 5f 6b 65 79 5f 61 75 70 5f 63 6f 75 6e 74 65 72 } //00 00 
		$a_00_5 = {5d 04 00 00 } //73 93 
	condition:
		any of ($a_*)
 
}