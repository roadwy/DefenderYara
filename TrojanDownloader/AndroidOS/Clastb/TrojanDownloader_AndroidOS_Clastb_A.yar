
rule TrojanDownloader_AndroidOS_Clastb_A{
	meta:
		description = "TrojanDownloader:AndroidOS/Clastb.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 65 72 53 65 72 76 69 63 65 24 73 74 61 72 74 24 31 } //01 00 
		$a_03_1 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 43 6f 6d 70 61 74 2e 42 75 69 6c 64 90 02 10 0a 20 20 20 20 20 20 20 20 20 20 20 90 02 10 2e 62 75 69 6c 64 28 29 90 00 } //01 00 
		$a_01_2 = {69 6e 73 74 61 6c 6c 41 70 70 3a 20 } //01 00 
		$a_01_3 = {61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 65 78 74 72 61 2e 4e 4f 54 5f 55 4e 4b 4e 4f 57 4e 5f 53 4f 55 52 43 45 } //01 00 
		$a_01_4 = {73 74 6f 70 46 6f 72 65 67 72 6f 75 6e 64 } //01 00 
		$a_01_5 = {67 65 74 45 78 74 65 72 6e 61 6c 46 69 6c 65 73 44 69 72 } //00 00 
	condition:
		any of ($a_*)
 
}