
rule TrojanDownloader_BAT_Heracles_ARAC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 1a 2c 04 17 58 0a 06 08 8e 69 32 e0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}