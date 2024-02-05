
rule TrojanDownloader_O97M_Powdow_UK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.UK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 43 65 6c 6c 73 28 37 2c 20 31 29 2c 20 41 32 2c 20 22 22 2c 20 22 22 2c 20 30 } //01 00 
		$a_01_1 = {3d 20 72 65 76 20 26 20 4d 69 64 28 66 49 6f 70 4e 43 74 2c 20 70 2c 20 31 29 } //01 00 
		$a_01_2 = {3d 20 66 44 79 54 28 68 38 37 64 66 30 30 28 29 2c 20 43 65 6c 6c 73 28 36 2c 20 31 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}