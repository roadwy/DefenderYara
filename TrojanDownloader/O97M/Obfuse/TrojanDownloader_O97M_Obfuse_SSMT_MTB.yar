
rule TrojanDownloader_O97M_Obfuse_SSMT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SSMT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 79 46 69 6c 65 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 75 70 64 61 74 65 2e 6a 73 } //01 00  myFile = "C:\Users\Public\update.js
		$a_03_1 = {44 65 62 75 67 2e 41 73 73 65 72 74 20 56 42 41 2e 53 68 65 6c 6c 28 61 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 90 02 03 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_2 = {3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 73 68 69 74 22 29 2e 52 61 6e 67 65 28 22 4b 33 33 35 22 29 } //00 00  = Worksheets("shit").Range("K335")
	condition:
		any of ($a_*)
 
}