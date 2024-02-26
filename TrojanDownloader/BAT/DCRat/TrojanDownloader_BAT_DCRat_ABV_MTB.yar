
rule TrojanDownloader_BAT_DCRat_ABV_MTB{
	meta:
		description = "TrojanDownloader:BAT/DCRat.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 04 00 "
		
	strings :
		$a_03_0 = {26 16 28 24 90 01 02 0a 72 21 90 01 02 70 28 25 90 01 02 0a 26 17 0c 16 90 0a 44 00 73 0e 90 01 02 06 0a 28 23 90 01 02 0a 0b 1f 1a 28 24 90 01 02 0a 72 0d 90 01 02 70 28 25 90 01 01 00 0a 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } //01 00  DownloadFileAsync
		$a_01_2 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00  GetFolderPath
		$a_01_3 = {54 61 73 6b 32 37 4c 6f 61 64 65 72 } //00 00  Task27Loader
	condition:
		any of ($a_*)
 
}