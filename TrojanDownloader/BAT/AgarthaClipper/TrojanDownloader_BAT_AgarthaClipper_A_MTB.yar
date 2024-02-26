
rule TrojanDownloader_BAT_AgarthaClipper_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgarthaClipper.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 11 04 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 2b 6f 90 01 01 00 00 0a 28 90 01 01 00 00 2b 02 7b 90 01 01 00 00 04 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 26 14 14 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}