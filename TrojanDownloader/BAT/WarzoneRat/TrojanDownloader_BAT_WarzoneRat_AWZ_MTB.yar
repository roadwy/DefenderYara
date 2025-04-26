
rule TrojanDownloader_BAT_WarzoneRat_AWZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/WarzoneRat.AWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 12 00 7e ?? 00 00 04 06 6f ?? 00 00 0a 00 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}