
rule TrojanDownloader_BAT_Bladabi_RS_MTB{
	meta:
		description = "TrojanDownloader:BAT/Bladabi.RS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 03 07 18 6f 03 00 00 0a 1f 10 28 04 00 00 0a 6f 05 00 00 0a 07 18 58 1d 2d 03 26 2b 03 0b 2b 00 07 03 6f 06 00 00 0a 32 d6 06 6f 07 00 00 0a 2a } //01 00 
		$a_01_1 = {34 00 31 00 2e 00 32 00 31 00 36 00 2e 00 31 00 38 00 33 00 2e 00 32 00 33 00 35 00 } //00 00  41.216.183.235
	condition:
		any of ($a_*)
 
}