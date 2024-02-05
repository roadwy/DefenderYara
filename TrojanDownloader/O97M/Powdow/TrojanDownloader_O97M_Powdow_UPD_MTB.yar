
rule TrojanDownloader_O97M_Powdow_UPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.UPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 33 2e 37 30 2e 32 34 37 2e 32 32 39 2f 90 02 05 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 90 02 1f 2e 62 61 74 22 22 20 90 02 20 2e 65 78 65 2e 65 78 65 20 26 26 20 90 02 20 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}