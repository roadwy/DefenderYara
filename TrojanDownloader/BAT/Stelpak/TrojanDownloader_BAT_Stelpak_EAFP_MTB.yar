
rule TrojanDownloader_BAT_Stelpak_EAFP_MTB{
	meta:
		description = "TrojanDownloader:BAT/Stelpak.EAFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0b 28 1b 00 00 0a 11 04 11 0b 1e 6f 1c 00 00 0a 17 8d 23 00 00 01 6f 1d 00 00 0a 13 0c 28 1b 00 00 0a 11 0c 6f 1e 00 00 0a 28 1f 00 00 0a 72 ea 00 00 70 28 20 00 00 0a 39 3c 00 00 00 11 04 11 0b 1f 14 58 28 1a 00 00 0a 13 0d 11 04 11 0b 1f 10 58 28 1a 00 00 0a 13 0e 11 0e 8d 1b 00 00 01 0b 11 04 11 0d 6e 07 16 6a 11 0e 6e 28 21 00 00 0a 17 13 09 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}