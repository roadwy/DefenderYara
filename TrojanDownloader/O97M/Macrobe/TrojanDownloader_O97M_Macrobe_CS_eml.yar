
rule TrojanDownloader_O97M_Macrobe_CS_eml{
	meta:
		description = "TrojanDownloader:O97M/Macrobe.CS!eml,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 53 68 65 6c 6c 28 45 6e 76 69 72 6f 6e 28 43 68 72 24 28 90 02 06 2d 90 02 05 29 20 26 20 43 68 72 24 28 90 02 06 2d 90 02 06 29 20 26 20 43 68 72 24 28 90 02 06 2d 90 02 06 29 20 26 20 43 68 72 24 28 90 02 06 2d 90 02 06 29 29 20 26 20 22 5c 90 02 50 22 29 90 00 } //01 00 
		$a_03_1 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 31 29 2e 4f 4c 45 46 6f 72 6d 61 74 2e 4f 70 65 6e 90 02 08 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 00 } //01 00 
		$a_01_2 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //01 00 
		$a_03_3 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 02 08 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 02 64 44 69 6d 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}