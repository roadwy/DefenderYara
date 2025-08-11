
rule TrojanDownloader_BAT_Ader_ADXA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.ADXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 91 02 08 07 5d 6f ?? 00 00 0a 61 d2 9c 16 2d e9 1a 2c e6 08 17 58 0c 08 03 8e 69 32 dc 06 2a 03 2b c0 0a 2b c6 02 2b c5 6f ?? 00 00 0a 2b c0 0b 2b bf 0c 2b bf 06 2b c3 08 2b c2 03 2b c1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}