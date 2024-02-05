
rule TrojanDownloader_O97M_EncDoc_PAAF_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 6e 65 77 6d 61 63 72 6f 73 22 66 } //01 00 
		$a_01_1 = {65 77 61 74 65 72 2c 74 65 61 2c 63 6f 6b 65 65 2c 70 61 70 65 72 74 6f 77 65 6c 65 6e 64 66 } //01 00 
		$a_01_2 = {72 69 67 68 74 28 6a 65 6c 6c 79 2c 6c 65 6e 28 6a 65 6c 6c 79 29 2d 33 29 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 62 6f 6c 74 73 28 62 65 65 72 29 64 6f 6f 61 74 3d 6f 61 74 2b 73 6e 69 63 6b 65 72 73 28 63 68 65 65 73 65 63 61 6b 65 28 62 65 65 72 29 29 62 65 65 72 3d 63 68 6f 63 6f 63 61 6b 65 28 62 65 65 72 29 6c 6f 6f 70 77 68 69 6c 65 6c 65 6e 28 62 65 65 72 29 3e 30 } //00 00 
	condition:
		any of ($a_*)
 
}