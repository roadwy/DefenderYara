
rule TrojanDownloader_BAT_StormKitty_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/StormKitty.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 0a 11 03 11 01 6f 90 01 01 00 00 0a 11 02 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 74 90 01 01 00 00 01 28 05 00 00 06 38 90 00 } //02 00 
		$a_03_1 = {00 00 70 1a 3a 58 00 00 00 26 38 00 00 00 00 72 90 01 01 00 00 70 13 02 38 90 00 } //02 00 
		$a_01_2 = {8e 69 5d 91 02 11 03 91 61 d2 9c 38 } //01 00 
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_4 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_5 = {67 65 74 5f 41 53 43 49 49 } //00 00  get_ASCII
	condition:
		any of ($a_*)
 
}