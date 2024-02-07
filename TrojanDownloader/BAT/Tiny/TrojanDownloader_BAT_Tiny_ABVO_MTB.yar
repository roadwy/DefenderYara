
rule TrojanDownloader_BAT_Tiny_ABVO_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ABVO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {0d 07 09 1a 16 6f 90 01 01 00 00 0a 26 09 16 28 90 01 01 00 00 0a 13 04 11 04 1b 58 8d 90 01 01 00 00 01 13 05 16 13 06 38 90 01 01 00 00 00 11 06 07 11 05 11 06 1b 58 11 04 11 06 59 20 00 10 00 00 3c 90 01 01 00 00 00 11 04 11 06 59 38 90 01 01 00 00 00 20 00 10 00 00 16 6f 90 01 01 00 00 0a 58 13 06 11 06 11 04 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}