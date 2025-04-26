
rule TrojanDownloader_BAT_Small_MVC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.MVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {17 8d 1a 00 00 01 0a 06 16 72 2d 00 00 70 a2 06 73 1e 00 00 0a 80 01 00 00 04 } //1
		$a_00_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}