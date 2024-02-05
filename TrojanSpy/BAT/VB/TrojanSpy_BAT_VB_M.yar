
rule TrojanSpy_BAT_VB_M{
	meta:
		description = "TrojanSpy:BAT/VB.M,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 4b 65 79 73 63 72 61 6d 62 6c 65 72 } //04 00 
		$a_01_1 = {41 6e 74 69 4d 61 6c 77 61 72 65 62 79 74 65 73 } //02 00 
		$a_01_2 = {4d 61 69 6c 41 64 64 72 65 73 73 43 6f 6c 6c 65 63 74 69 6f 6e } //02 00 
		$a_01_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}