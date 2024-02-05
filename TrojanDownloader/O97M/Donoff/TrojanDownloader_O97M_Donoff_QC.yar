
rule TrojanDownloader_O97M_Donoff_QC{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QC,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 22 20 26 } //01 00 
		$a_01_1 = {3d 20 53 68 65 6c 6c 28 22 77 73 63 72 22 20 26 20 22 69 70 74 20 22 20 26 } //01 00 
		$a_01_2 = {2e 57 61 69 74 20 28 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 3a 30 30 3a 31 30 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_QC_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QC,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //Sub Auto_Open()  03 00 
		$a_03_1 = {47 65 74 46 69 6c 65 4f 6e 28 22 90 02 20 3a 2f 2f 74 68 65 2e 90 02 10 65 61 72 74 68 2e 6c 69 90 02 10 2f 7e 73 67 74 61 74 68 61 6d 90 02 10 2f 70 75 90 02 10 74 74 79 2f 6c 61 74 65 90 02 10 73 74 90 02 10 2f 78 38 36 2f 70 90 02 10 75 74 74 79 90 02 10 2e 90 02 10 65 90 02 10 78 90 02 10 65 22 2c 20 45 6e 76 69 72 6f 6e 28 22 90 02 10 22 29 20 26 20 22 5c 90 02 20 2e 65 78 65 22 29 20 3d 20 54 72 75 65 90 00 } //03 00 
		$a_03_2 = {43 61 6c 6c 20 53 76 69 65 72 28 45 6e 76 69 72 6f 6e 28 22 90 02 10 22 29 20 26 20 22 5c 90 02 20 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}