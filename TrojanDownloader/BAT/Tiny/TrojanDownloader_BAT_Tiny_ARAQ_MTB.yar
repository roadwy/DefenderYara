
rule TrojanDownloader_BAT_Tiny_ARAQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {1a 2c 2b 11 04 09 11 05 09 8e 69 5d 91 08 11 05 91 61 d2 6f 90 01 03 0a 11 05 17 58 13 05 11 05 08 8e 69 32 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}