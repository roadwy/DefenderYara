
rule TrojanDownloader_O97M_Donoff_CS{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CS,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 90 1d 0f 00 28 90 02 50 29 20 41 73 20 53 74 72 69 6e 67 90 02 0f 90 1b 00 20 3d 20 90 12 09 00 2e 90 12 0f 00 2e 54 65 78 74 20 26 20 22 20 22 20 26 20 90 12 09 00 28 90 1b 04 2e 90 12 0f 00 2e 54 65 78 74 29 90 02 0f 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 02 1f 90 1b 06 28 90 12 09 00 20 41 73 20 53 74 72 69 6e 67 29 90 02 1f 3d 20 53 74 72 52 65 76 65 72 73 65 28 54 72 69 6d 28 90 1b 0c 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}