
rule TrojanDownloader_BAT_Dae_YA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Dae.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 06 00 00 06 6f 90 01 01 00 00 0a 72 90 01 01 00 00 70 72 90 01 01 00 00 70 16 28 90 01 01 00 00 0a 20 90 01 02 00 00 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 26 02 6f 19 00 00 06 16 6f 90 01 01 00 00 0a 00 02 6f 1b 00 00 06 17 6f 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //00 00  DownloadFile
	condition:
		any of ($a_*)
 
}