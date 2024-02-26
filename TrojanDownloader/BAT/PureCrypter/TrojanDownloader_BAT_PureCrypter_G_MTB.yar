
rule TrojanDownloader_BAT_PureCrypter_G_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureCrypter.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 3f b6 3f 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 8a 01 00 00 86 00 00 00 98 05 00 00 2f 05 } //02 00 
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 41 00 73 00 79 00 6e 00 63 00 } //00 00  DownloadAsync
	condition:
		any of ($a_*)
 
}