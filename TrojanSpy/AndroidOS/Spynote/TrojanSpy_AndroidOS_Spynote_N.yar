
rule TrojanSpy_AndroidOS_Spynote_N{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.N,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 70 61 63 6b 61 67 65 2f 6e 61 6d 65 2f 6d 6d 73 69 61 61 79 6a 75 6d 71 62 73 62 68 77 66 72 79 6a 63 72 75 72 6e 78 75 6b 65 77 78 6f 7a 69 77 6a 74 6c 6f 32 34 33 39 } //02 00 
		$a_00_1 = {2f 66 73 6a 68 71 78 62 6b 6b 69 73 63 32 34 33 32 32 } //00 00 
	condition:
		any of ($a_*)
 
}