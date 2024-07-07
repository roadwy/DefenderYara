
rule TrojanDownloader_BAT_AsyncRAT_CA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 29 00 61 52 fe 0c 0d 00 20 01 00 00 00 58 fe 0e 90 01 01 00 fe 0c 26 00 20 01 00 00 00 58 fe 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}