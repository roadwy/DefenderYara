
rule TrojanDownloader_O97M_Donoff_DQ{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DQ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 62 6c 65 53 74 79 6c 65 } //01 00 
		$a_02_1 = {3d 20 22 22 20 54 68 65 6e 0d 0a 53 68 65 6c 6c 20 90 02 0f 2c 20 30 90 00 } //01 00 
		$a_02_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 90 02 0f 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}