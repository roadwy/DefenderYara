
rule Trojan_BAT_Downloader_SDV_MTB{
	meta:
		description = "Trojan:BAT/Downloader.SDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {04 0d 09 17 59 45 05 00 00 00 01 00 00 00 09 00 00 00 2b 00 00 00 35 00 00 00 3e 00 00 00 2a 28 90 01 03 0a 0a 2b 40 72 25 00 00 70 28 90 01 03 06 72 ce 00 00 70 28 90 01 03 06 14 28 90 01 03 0a 75 09 00 00 01 0a 2b 1e 1f 10 28 90 01 03 0a 0a 2b 14 1b 28 90 01 03 0a 0a 2b 0b 28 90 01 03 0a 6f 90 01 03 0a 0a 06 02 28 90 01 03 0a 10 00 02 28 90 01 03 0a 02 0e 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}