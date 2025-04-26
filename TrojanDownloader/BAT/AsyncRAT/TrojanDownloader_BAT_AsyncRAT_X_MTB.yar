
rule TrojanDownloader_BAT_AsyncRAT_X_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 38 ?? 00 00 00 38 ?? 00 00 00 20 80 00 00 00 38 ?? 00 00 00 38 ?? 00 00 00 72 ?? 00 00 70 38 ?? 00 00 00 7e ?? 00 00 04 20 e8 03 00 00 73 ?? 00 00 0a 0c 07 08 07 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 07 08 07 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}