
rule Trojan_BAT_Downloader_NE_MTB{
	meta:
		description = "Trojan:BAT/Downloader.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {15 2c 2a 73 29 00 00 0a 25 72 6d 00 00 70 6f 2a 00 00 0a 25 72 75 00 00 70 6f 2b 00 00 0a 25 17 6f 2c 00 00 0a 25 17 2b 0e 2b 13 2b 18 16 2d d0 16 2d cd 1b 2c ca 2a 6f 2d 00 00 0a 2b eb 28 2e 00 00 0a 2b e6 6f 2f 00 00 0a 2b e1 } //01 00 
		$a_01_1 = {50 2e 4f 2d 39 37 38 30 39 38 38 36 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}