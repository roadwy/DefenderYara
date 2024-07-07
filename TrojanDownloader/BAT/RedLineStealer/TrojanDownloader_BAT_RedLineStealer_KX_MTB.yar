
rule TrojanDownloader_BAT_RedLineStealer_KX_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 0c 08 6f 90 01 03 0a 20 00 01 00 00 14 14 14 6f 90 01 03 0a 26 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}