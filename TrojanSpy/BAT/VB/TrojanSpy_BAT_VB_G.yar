
rule TrojanSpy_BAT_VB_G{
	meta:
		description = "TrojanSpy:BAT/VB.G,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {5b 00 61 00 6c 00 74 00 20 00 67 00 72 00 5d 00 } //02 00 
		$a_00_1 = {5b 00 2f 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5d 00 } //03 00 
		$a_01_2 = {4b 42 44 4c 4c 48 4f 4f 4b 53 54 52 55 43 54 } //02 00 
		$a_01_3 = {76 69 72 74 75 61 6c 4b 65 79 } //01 00 
		$a_01_4 = {4b 65 79 62 6f 61 72 64 48 6f 6f 6b 44 65 6c 65 67 61 74 65 } //02 00 
		$a_01_5 = {4b 5f 4e 75 6d 70 61 64 33 } //00 00 
	condition:
		any of ($a_*)
 
}