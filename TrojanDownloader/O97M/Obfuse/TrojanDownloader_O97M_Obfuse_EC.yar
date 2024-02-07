
rule TrojanDownloader_O97M_Obfuse_EC{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EC,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 90 02 22 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 90 00 } //01 00 
		$a_01_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 30 30 30 36 46 30 33 41 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 22 29 } //01 00  = GetObject("new:0006F03A-0000-0000-C000-000000000046")
		$a_03_2 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 14 29 2e 52 75 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}