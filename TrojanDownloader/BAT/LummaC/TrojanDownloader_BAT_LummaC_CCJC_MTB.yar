
rule TrojanDownloader_BAT_LummaC_CCJC_MTB{
	meta:
		description = "TrojanDownloader:BAT/LummaC.CCJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 09 17 73 ?? ?? ?? ?? 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 10 00 de 18 11 05 2c 07 11 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}