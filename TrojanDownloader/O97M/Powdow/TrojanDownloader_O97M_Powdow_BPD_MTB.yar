
rule TrojanDownloader_O97M_Powdow_BPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 33 2e 31 31 32 2e 32 33 33 2e 31 39 39 2f 73 68 61 72 65 2f 90 02 18 2e 62 61 74 22 90 00 } //01 00 
		$a_03_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 90 02 1f 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}