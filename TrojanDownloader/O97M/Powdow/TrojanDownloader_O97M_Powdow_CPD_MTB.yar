
rule TrojanDownloader_O97M_Powdow_CPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.CPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 59 6b 72 77 4a 68 2f 52 46 5f 36 30 32 31 33 5f 33 37 38 30 5f 31 30 35 2e 62 61 74 22 } //01 00 
		$a_03_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 90 02 25 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}