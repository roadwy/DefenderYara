
rule TrojanDownloader_O97M_IcedID_JAO_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.JAO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {52 65 70 6c 61 63 65 28 90 02 08 2c 20 90 02 08 2c 20 22 22 29 90 00 } //03 00 
		$a_01_1 = {53 70 6c 69 74 28 22 6d 73 68 74 61 2e 65 78 65 7c 69 6e 2e 63 6f 6d 7c 69 6e 2e 68 74 6d 6c 22 2c 20 22 7c 22 29 } //01 00 
		$a_03_2 = {4d 69 64 28 90 02 08 2c 20 90 02 0f 2c 20 31 29 90 00 } //01 00 
		$a_03_3 = {4d 69 64 24 28 90 02 08 2c 20 90 02 08 2c 20 31 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_IcedID_JAO_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/IcedID.JAO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 06 00 00 03 00 "
		
	strings :
		$a_03_0 = {52 65 70 6c 61 63 65 28 90 02 08 2c 20 90 02 08 2c 20 22 22 29 90 00 } //03 00 
		$a_01_1 = {53 70 6c 69 74 28 22 6d 73 68 74 61 2e 65 78 65 7c 69 6e 2e 63 6f 6d 7c 69 6e 2e 68 74 6d 6c 22 2c 20 22 7c 22 29 } //02 00 
		$a_03_2 = {28 22 77 69 6e 64 69 72 22 29 20 26 20 90 02 08 20 26 20 22 73 79 73 74 65 6d 33 32 22 90 00 } //02 00 
		$a_03_3 = {28 22 77 69 6e 22 20 26 20 22 64 69 72 22 29 20 26 20 90 02 08 20 26 20 22 73 79 73 74 65 22 20 26 20 22 6d 33 32 90 00 } //01 00 
		$a_03_4 = {4d 69 64 28 90 02 08 2c 20 90 02 08 2c 20 31 29 90 00 } //01 00 
		$a_03_5 = {4d 69 64 24 28 90 02 08 2c 20 90 02 08 2c 20 31 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}