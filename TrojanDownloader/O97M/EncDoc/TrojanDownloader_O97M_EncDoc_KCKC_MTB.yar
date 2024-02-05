
rule TrojanDownloader_O97M_EncDoc_KCKC_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.KCKC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 6d 63 6b 69 6e 6e 65 79 74 69 67 68 65 2e 63 6f 6d 2f 6e 65 77 6d 6f 6e 2f 63 61 6c 63 2f 41 74 74 61 63 6b 2e 6a 70 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_KCKC_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.KCKC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 73 61 79 6d 69 6e 61 6d 65 2e 63 6f 6d 2f 6e 65 77 2f 70 72 6f 63 65 73 73 2e 65 78 65 22 22 20 90 02 1f 2e 65 78 65 2e 65 78 65 20 26 26 20 90 02 1f 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}