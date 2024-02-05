
rule Trojan_BAT_Downloader_DEGA_MTB{
	meta:
		description = "Trojan:BAT/Downloader.DEGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {73 27 00 00 0a 0b 1e 8d 29 00 00 01 13 07 11 07 16 17 9c 11 07 17 18 9c 11 07 18 19 9c 11 07 19 1a 9c 11 07 1a 1b 9c 11 07 1b 1c 9c 11 07 1c 1d 9c 11 07 1d 1e 9c 11 07 13 05 72 1e 01 00 70 11 05 73 28 90 01 03 0d 07 09 07 6f 90 01 03 0a 8e b7 6f 90 01 03 0a 6f 90 01 03 0a 00 07 09 07 6f 90 01 03 0a 8e b7 6f 90 01 03 0a 6f 90 01 03 0a 00 73 2e 00 00 0a 13 06 11 06 07 6f 90 01 03 0a 17 73 30 00 00 0a 0a 00 03 28 90 01 03 0a 13 04 06 11 04 16 11 04 8e b7 6f 90 01 03 0a 00 06 6f 90 01 03 0a 00 28 90 01 03 0a 11 06 6f 90 01 03 0a 6f 90 01 03 0a 0c de 10 de 0d 28 90 01 03 0a 00 28 90 01 03 0a de 00 00 08 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}