
rule Trojan_BAT_PsDownloader_PSTR_MTB{
	meta:
		description = "Trojan:BAT/PsDownloader.PSTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 06 00 00 0a 0a 06 6f 90 01 01 00 00 0a 16 9a 0b 7e 08 00 00 0a 0c 06 07 6f 90 01 01 00 00 0a 0d 09 73 0a 00 00 0a 13 04 11 04 6f 90 01 01 00 00 0a 0c de 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}