
rule TrojanDownloader_O97M_RevengeRAT_RV_MTB{
	meta:
		description = "TrojanDownloader:O97M/RevengeRAT.RV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 70 74 2e 74 65 78 74 62 69 6e 2e 6e 65 74 2f 64 6f 77 6e 6c 6f 61 64 2f 69 74 6d 31 64 6b 67 7a 37 63 27 29 3b } //01 00  ttps://pt.textbin.net/download/itm1dkgz7c');
		$a_03_1 = {63 61 6c 6c 73 68 65 6c 6c 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2d 63 6f 6d 6d 61 6e 64 22 26 90 02 14 26 22 3b 65 78 69 74 22 2c 76 62 68 69 64 65 29 90 00 } //01 00 
		$a_01_2 = {73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 } //00 00  subauto_open()
	condition:
		any of ($a_*)
 
}