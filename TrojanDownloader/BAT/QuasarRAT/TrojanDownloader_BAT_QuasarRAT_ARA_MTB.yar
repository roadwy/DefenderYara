
rule TrojanDownloader_BAT_QuasarRAT_ARA_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 06 02 08 6f ?? ?? ?? 0a 03 08 07 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 00 08 17 58 0c 08 02 6f ?? ?? ?? 0a fe 04 0d 09 2d d4 } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } //2 DownloadFileAsync
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}