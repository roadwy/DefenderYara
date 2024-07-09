
rule TrojanDownloader_BAT_Wagex_AW_MTB{
	meta:
		description = "TrojanDownloader:BAT/Wagex.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 18 2d 03 26 2b 1b 0a 2b fb 00 02 72 01 00 00 70 28 ?? ?? ?? 06 1a 2d 03 26 de 06 0a 2b fb 26 de 00 06 2c e5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_BAT_Wagex_AW_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Wagex.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 20 09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 18 2c bd 11 04 15 2c da 17 58 13 04 11 04 07 8e 16 2d 01 69 32 d6 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}