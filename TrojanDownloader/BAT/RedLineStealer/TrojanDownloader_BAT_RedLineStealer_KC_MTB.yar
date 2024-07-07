
rule TrojanDownloader_BAT_RedLineStealer_KC_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 91 72 90 01 01 00 00 70 28 90 01 01 00 00 90 01 01 59 d2 9c 20 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}