
rule TrojanDownloader_O97M_Powdow_PDOH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDOH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 3a 2f 2f 34 35 2e 31 35 35 2e 31 36 35 2e 36 33 2f 90 02 03 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 90 02 25 2e 65 78 65 22 22 90 02 1f 2e 65 78 65 2e 65 78 65 26 26 90 1b 02 2e 65 78 65 2e 65 78 65 22 2c 76 62 68 69 64 65 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}