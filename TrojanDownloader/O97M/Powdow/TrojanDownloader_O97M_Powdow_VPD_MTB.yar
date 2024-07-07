
rule TrojanDownloader_O97M_Powdow_VPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.VPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 77 77 77 2e 73 61 72 61 68 62 75 72 72 65 6c 6c 2e 69 6e 66 6f 2f 6e 64 78 7a 73 74 75 64 69 6f 2f 6c 61 6e 67 2f 65 73 2d 65 73 2f 90 02 0a 2e 65 78 65 22 22 20 90 02 1f 2e 65 78 65 2e 65 78 65 20 26 26 20 90 1b 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}