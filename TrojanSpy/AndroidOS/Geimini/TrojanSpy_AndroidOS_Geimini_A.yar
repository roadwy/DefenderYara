
rule TrojanSpy_AndroidOS_Geimini_A{
	meta:
		description = "TrojanSpy:AndroidOS/Geimini.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 69 2c 78 69 61 6f 6c 75 90 01 02 68 69 2c 6c 69 71 69 61 6e 90 01 02 63 6f 6d 6d 61 6e 64 20 6f 6b 90 01 02 62 79 65 90 00 } //01 00 
		$a_03_1 = {41 64 41 63 74 69 76 69 74 79 90 09 0c 00 63 6f 6d 90 03 01 01 2e 2f 67 65 69 6e 69 6d 69 90 00 } //01 00 
		$a_01_2 = {70 72 6f 63 65 73 73 44 4f 57 4e 4c 4f 41 44 5f 46 41 49 4c 55 45 5f 41 63 74 69 6f 6e } //01 00 
		$a_01_3 = {70 72 6f 63 65 73 73 50 41 52 53 45 5f 46 41 49 4c 55 45 5f 41 63 74 69 6f 6e } //01 00 
		$a_01_4 = {54 52 41 4e 53 41 43 54 5f 46 41 49 4c 55 45 } //00 00 
	condition:
		any of ($a_*)
 
}