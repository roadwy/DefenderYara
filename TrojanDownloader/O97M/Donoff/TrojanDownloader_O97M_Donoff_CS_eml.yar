
rule TrojanDownloader_O97M_Donoff_CS_eml{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CS!eml,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 57 69 63 6d 64 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00 
		$a_01_1 = {57 69 63 6d 64 2e 43 72 65 61 74 65 46 6f 6c 64 65 72 20 22 43 3a 5c 49 6d 67 43 6f 6e 74 65 6e 74 5c 22 } //01 00 
		$a_03_2 = {47 61 6c 6c 65 72 79 35 39 2e 63 6d 64 22 90 0a 23 00 22 43 3a 5c 49 6d 67 43 6f 6e 74 65 6e 74 5c 90 00 } //01 00 
		$a_03_3 = {5c 57 72 69 74 65 4c 69 6e 65 73 2e 65 78 65 22 90 0a 26 00 73 74 61 72 74 20 43 3a 5c 49 6d 67 43 6f 6e 74 65 6e 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}