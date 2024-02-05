
rule TrojanDownloader_O97M_Dridex_RDX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.RDX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 20 3d 20 6b 20 2b 20 43 68 72 28 73 2e 43 6f 6c 75 6d 6e 29 } //01 00 
		$a_03_1 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 52 65 70 6c 61 63 65 28 90 02 0f 2c 20 22 3f 22 2c 20 70 69 70 6f 29 90 00 } //01 00 
		$a_01_2 = {3d 20 53 70 6c 69 74 28 74 28 30 29 2c 20 22 21 22 29 } //01 00 
		$a_01_3 = {65 63 67 68 6f 20 3d 20 53 70 6c 69 74 28 6e 61 6d 65 72 2c 20 22 21 22 29 } //01 00 
		$a_01_4 = {53 75 62 20 65 70 73 6f 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}