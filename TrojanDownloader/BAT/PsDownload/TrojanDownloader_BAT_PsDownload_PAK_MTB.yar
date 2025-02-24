
rule TrojanDownloader_BAT_PsDownload_PAK_MTB{
	meta:
		description = "TrojanDownloader:BAT/PsDownload.PAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 6f ?? 00 00 0a 06 72 17 00 00 70 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 28 ?? 00 00 0a 26 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}