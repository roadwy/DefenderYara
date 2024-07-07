
rule TrojanDownloader_BAT_AsyncRAT_BN_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 00 04 06 91 20 69 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}