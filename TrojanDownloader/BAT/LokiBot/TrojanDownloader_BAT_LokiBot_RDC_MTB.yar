
rule TrojanDownloader_BAT_LokiBot_RDC_MTB{
	meta:
		description = "TrojanDownloader:BAT/LokiBot.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 07 8e 69 5d 91 02 09 91 61 d2 6f ?? ?? ?? 0a 09 17 58 0d 09 02 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}