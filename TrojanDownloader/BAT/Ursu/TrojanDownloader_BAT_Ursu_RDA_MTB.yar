
rule TrojanDownloader_BAT_Ursu_RDA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ursu.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {17 6f 1f 00 00 0a 25 6f 1d 00 00 0a 17 6f 20 00 00 0a 6f 1d 00 00 0a 17 } //00 00 
	condition:
		any of ($a_*)
 
}