
rule TrojanDownloader_O97M_EncDoc_PABD_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PABD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 73 3a 2f 2f 6b 6e 67 31 64 34 2e 78 79 7a 2f 77 72 66 70 6e 71 62 74 2f 67 7a 6a 75 6e 73 6c 66 70 6f 30 38 37 38 35 35 2e 65 78 65 22 22 90 02 2f 2e 65 78 65 2e 65 78 65 26 26 90 1b 00 2e 65 78 65 2e 65 78 65 22 2c 76 62 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}