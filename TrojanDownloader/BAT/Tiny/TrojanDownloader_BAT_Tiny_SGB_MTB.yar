
rule TrojanDownloader_BAT_Tiny_SGB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.SGB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_1 = {64 00 61 00 6d 00 6e 00 2e 00 52 00 75 00 6e 00 50 00 45 00 } //1 damn.RunPE
		$a_01_2 = {63 00 61 00 74 00 6c 00 61 00 6b 00 } //1 catlak
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}