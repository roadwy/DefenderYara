
rule TrojanDownloader_O97M_EncDoc_PAK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 66 65 65 64 62 61 63 6b 69 6e 67 22 } //01 00 
		$a_01_1 = {69 3d 6c 62 6f 75 6e 64 28 6c 69 6e 2c 31 29 74 6f 75 62 6f 75 6e 64 28 6c 69 6e 2c 31 29 74 65 73 74 3d 74 65 73 74 2b 69 66 69 65 3d 73 70 6c 69 74 28 6c 69 6e 28 69 29 2c 22 7c 22 2c 33 } //01 00 
		$a_01_2 = {70 72 6f 63 65 73 73 69 6e 67 73 28 6f 62 6a 2e 72 65 73 70 6f 6e 73 65 74 65 78 74 29 65 6e 64 69 66 65 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}