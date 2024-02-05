
rule TrojanDownloader_BAT_Wagex_MBDF_MTB{
	meta:
		description = "TrojanDownloader:BAT/Wagex.MBDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 08 16 19 2d 06 17 2c 6a 26 2b 6d 16 2d 6b 2b 76 2b f7 00 } //01 00 
		$a_01_1 = {70 2b 28 1e 2d 1b 26 2b 29 2b 2e 2b 2f } //00 00 
	condition:
		any of ($a_*)
 
}