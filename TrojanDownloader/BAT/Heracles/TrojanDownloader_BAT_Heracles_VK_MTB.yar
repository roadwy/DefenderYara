
rule TrojanDownloader_BAT_Heracles_VK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 8d 17 00 00 01 13 04 09 11 04 16 08 6f 13 00 00 0a 26 11 04 28 01 00 00 2b 28 02 00 00 2b 13 05 de 14 } //00 00 
	condition:
		any of ($a_*)
 
}