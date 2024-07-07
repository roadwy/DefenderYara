
rule TrojanDownloader_BAT_PsDownload_CXD_MTB{
	meta:
		description = "TrojanDownloader:BAT/PsDownload.CXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 13 00 00 0a 72 90 01 04 28 90 01 04 6f 90 01 04 28 90 01 04 0b 07 16 07 8e 69 28 90 01 04 07 0c de 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}