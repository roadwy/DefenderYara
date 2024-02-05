
rule TrojanDownloader_O97M_Powdow_RSR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RSR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 4d 44 20 20 2f 63 20 50 4f 57 65 72 53 68 65 6c 6c 2e 45 58 45 20 20 2d 65 78 20 62 59 50 41 53 53 20 2d 4e 4f 50 20 2d 77 20 31 20 49 45 78 28 20 43 55 72 4c } //01 00 
		$a_00_1 = {68 74 74 70 27 20 20 2b 20 27 3a 2f 2f 34 35 2e 31 34 35 2e 31 38 35 2e 31 35 33 27 20 20 2b 20 27 2f 46 69 6c 65 27 20 20 2b 20 27 44 6f 63 27 20 20 2b 20 27 2e 27 20 20 2b 20 27 6a 27 20 20 2b 20 27 70 27 20 20 2b 20 27 67 27 } //00 00 
	condition:
		any of ($a_*)
 
}