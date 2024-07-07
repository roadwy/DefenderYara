
rule TrojanDownloader_BAT_AsyncRAT_CN_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 20 00 01 00 00 14 fe 09 90 01 01 00 71 90 01 01 00 00 01 fe 09 90 01 01 00 71 90 01 01 00 00 01 74 90 01 01 00 00 1b 6f 90 01 01 00 00 0a 26 fe 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}