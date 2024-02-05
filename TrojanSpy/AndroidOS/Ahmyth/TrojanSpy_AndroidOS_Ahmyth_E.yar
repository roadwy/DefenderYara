
rule TrojanSpy_AndroidOS_Ahmyth_E{
	meta:
		description = "TrojanSpy:AndroidOS/Ahmyth.E,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 61 68 6d 79 74 68 2f 6d 69 6e 65 2f 6b 69 6e 67 2f 61 68 6d 79 74 68 2f 43 6f 6e 6e 65 63 74 69 6f 6e 4d 61 6e 61 67 65 72 3b } //02 00 
		$a_01_1 = {41 68 4d 79 74 68 27 73 20 69 63 6f 6e 20 68 61 73 20 62 65 65 6e 20 72 65 76 65 61 6c 65 64 21 } //02 00 
		$a_01_2 = {78 30 30 30 30 73 6d } //00 00 
	condition:
		any of ($a_*)
 
}