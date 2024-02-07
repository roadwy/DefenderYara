
rule TrojanDownloader_O97M_Obfuse_GZ{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GZ,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00  Sub AutoOpen()
		$a_03_1 = {22 6e 65 77 3a 22 20 2b 20 90 02 14 28 31 29 2e 56 61 6c 75 65 90 00 } //01 00 
		$a_03_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 90 02 14 28 32 29 2c 20 22 22 2c 90 00 } //01 00 
		$a_03_3 = {2e 52 75 6e 21 20 90 02 12 2c 20 30 20 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}