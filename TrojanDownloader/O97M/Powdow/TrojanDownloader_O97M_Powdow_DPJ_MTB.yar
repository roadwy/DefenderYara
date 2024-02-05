
rule TrojanDownloader_O97M_Powdow_DPJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DPJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 22 28 27 68 74 74 70 73 3a 2f 2f 70 6c 61 7a 61 62 6f 75 6c 65 76 61 72 64 2e 63 6f 6d 2e 62 72 2f 64 6f 67 2e 70 64 66 27 29 2d 22 2b 22 75 22 2b 22 73 22 2b 22 3f 22 2b 22 62 22 2b } //01 00 
		$a_03_1 = {61 75 74 6f 5f 63 6c 6f 73 65 28 29 6d 73 67 62 6f 78 22 65 72 72 6f 72 21 22 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 90 02 20 3a 63 61 6c 6c 73 68 65 6c 6c 23 28 2c 30 29 65 6e 64 73 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}