
rule TrojanDownloader_BAT_Small_MVB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.MVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 07 17 28 24 00 00 0a 28 25 00 00 0a 20 80 } //1
		$a_00_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}