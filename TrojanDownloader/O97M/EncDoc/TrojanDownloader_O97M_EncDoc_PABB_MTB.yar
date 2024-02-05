
rule TrojanDownloader_O97M_EncDoc_PABB_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PABB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 75 62 66 6f 63 75 73 77 6f 72 6b 28 29 64 69 6d 6b 6f 6f 6f 6f 6c 6c 6c 6c 6c 6c 6c 6c 66 } //01 00 
		$a_01_1 = {6d 65 74 61 3d 77 6f 72 6b 73 68 65 65 74 73 28 22 62 6c 61 6e 6b 65 64 31 22 29 2e 72 61 6e 67 65 28 22 61 31 30 33 30 22 29 2b 77 6f 72 6b 73 68 65 65 74 73 28 22 62 6c 61 6e 6b 65 64 31 22 29 2e 72 61 6e 67 65 28 22 62 31 30 33 22 29 70 } //01 00 
		$a_01_2 = {67 6f 6e 65 3d 22 77 73 63 72 69 70 74 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 70 69 63 74 75 72 65 73 5c 66 6f 63 75 73 2e 6a 73 22 63 61 6c 6c 76 62 61 2e 73 68 65 6c 6c 28 6f 6e 65 2c 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 29 65 6e 64 73 } //00 00 
	condition:
		any of ($a_*)
 
}