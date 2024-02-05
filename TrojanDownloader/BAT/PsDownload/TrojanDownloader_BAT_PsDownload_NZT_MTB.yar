
rule TrojanDownloader_BAT_PsDownload_NZT_MTB{
	meta:
		description = "TrojanDownloader:BAT/PsDownload.NZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 1c 2d 03 26 2b 03 0b 2b 00 06 16 73 90 01 03 0a 73 90 01 03 0a 17 2d 03 26 2b 03 0c 2b 90 00 } //01 00 
		$a_01_1 = {38 00 39 00 2e 00 33 00 34 00 2e 00 32 00 37 00 2e 00 31 00 36 00 37 00 2f 00 77 00 69 00 72 00 65 00 67 } //00 00 
	condition:
		any of ($a_*)
 
}