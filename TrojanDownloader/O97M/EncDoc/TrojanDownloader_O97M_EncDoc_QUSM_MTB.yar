
rule TrojanDownloader_O97M_EncDoc_QUSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.QUSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 22 22 66 6f 72 6b 3d 30 74 6f 6c 65 6e 28 73 29 2d 31 73 68 69 66 74 3d 28 61 73 63 28 6d 69 64 28 6b 65 79 2c 28 6b 6d 6f 64 6c 65 6e 28 6b 65 79 29 29 2b 31 2c 31 29 29 6d 6f 64 6c 65 6e 28 73 29 29 2b 31 90 02 1f 3d 90 1b 00 26 6d 69 64 28 73 2c 73 68 69 66 74 2c 31 29 73 3d 90 02 1f 28 73 2c 73 68 69 66 74 29 6e 65 78 74 6b 65 6e 64 66 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_01_1 = {66 6f 72 3d 30 74 6f 28 29 2d 31 73 74 65 70 32 3d 2f 32 28 29 3d 32 35 35 2d 28 26 28 2c 29 26 28 2c 2b 31 29 29 6e 65 78 74 3d 65 6e 64 66 75 6e 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}