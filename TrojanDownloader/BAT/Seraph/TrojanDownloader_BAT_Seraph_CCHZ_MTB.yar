
rule TrojanDownloader_BAT_Seraph_CCHZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 0b 2b 10 de 14 73 90 01 03 0a 2b ee 28 90 01 01 00 00 0a 2b ee 0a 2b ed 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}