
rule TrojanDownloader_O97M_EncDoc_AMDF_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AMDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {70 22 26 22 73 3a 2f 2f 90 02 df 22 2c 22 90 00 } //01 00 
		$a_03_1 = {70 22 26 22 73 22 26 22 3a 2f 2f 90 02 df 22 2c 22 90 00 } //01 00 
		$a_03_2 = {70 22 26 22 3a 2f 22 26 22 2f 90 02 df 22 2c 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_AMDF_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AMDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 22 26 22 74 70 22 26 22 73 3a 2f 2f 90 02 df 2f 22 2c 22 90 02 0a 74 22 26 22 74 22 26 22 70 3a 2f 2f 90 02 df 2f 22 2c 22 90 02 0a 74 74 22 26 22 70 3a 2f 2f 90 02 df 2f 22 2c 22 90 02 0a 74 22 26 22 74 22 26 22 70 3a 2f 2f 90 02 df 2f 22 2c 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_AMDF_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AMDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 74 70 3a 2f 2f 6c 65 61 72 6e 76 69 61 6f 6e 6c 69 6e 65 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 71 47 62 2f } //01 00 
		$a_01_1 = {74 74 70 3a 2f 2f 6b 6f 6c 65 6a 6c 65 72 69 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 52 45 76 75 70 2f } //01 00 
		$a_01_2 = {74 74 70 3a 2f 2f 73 74 61 69 6e 65 64 67 6c 61 73 73 65 78 70 72 65 73 73 2e 63 6f 6d 2f 63 6c 61 73 73 65 73 2f 30 35 53 6b 69 69 57 39 79 34 44 44 47 76 62 36 2f } //01 00 
		$a_01_3 = {74 74 70 3a 2f 2f 6d 69 6c 61 6e 73 74 61 66 66 69 6e 67 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 44 34 54 52 6e 44 75 62 46 2f } //00 00 
	condition:
		any of ($a_*)
 
}