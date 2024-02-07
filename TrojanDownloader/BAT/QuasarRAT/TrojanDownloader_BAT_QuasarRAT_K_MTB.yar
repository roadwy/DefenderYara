
rule TrojanDownloader_BAT_QuasarRAT_K_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 00 0a 13 05 38 } //02 00 
		$a_01_1 = {11 02 11 07 11 01 02 11 07 18 5a 18 } //02 00  ȑܑđᄂ᠇ᡚ
		$a_03_2 = {00 00 0a 18 5b 8d 90 01 01 00 00 01 13 02 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}