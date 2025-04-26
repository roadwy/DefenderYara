
rule TrojanDownloader_BAT_LummaC_CCJR_MTB{
	meta:
		description = "TrojanDownloader:BAT/LummaC.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 36 11 2c 25 17 58 13 2c 11 18 11 14 91 11 18 11 14 17 58 91 1e 62 60 d1 9d 11 14 18 58 13 14 11 14 11 0b 32 da } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}