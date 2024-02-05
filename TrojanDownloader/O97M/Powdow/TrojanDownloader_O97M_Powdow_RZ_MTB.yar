
rule TrojanDownloader_O97M_Powdow_RZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 6e 76 69 72 6f 6e 28 22 55 53 45 52 4e 41 4d 45 22 29 } //01 00 
		$a_02_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 90 02 05 2c 20 76 62 48 69 64 65 29 90 00 } //01 00 
		$a_00_2 = {68 74 74 70 3a 2f 2f 6c 6f 63 61 6c 68 6f 73 74 3a 38 30 30 30 2f 63 6d 64 2e 65 78 65 } //01 00 
		$a_02_3 = {54 65 6d 70 5c 64 66 64 66 64 2e 65 78 65 90 0a 3c 00 53 74 61 72 74 2d 50 72 6f 63 65 73 73 28 27 43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}