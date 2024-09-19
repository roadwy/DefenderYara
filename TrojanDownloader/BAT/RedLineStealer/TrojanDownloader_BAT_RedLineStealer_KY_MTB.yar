
rule TrojanDownloader_BAT_RedLineStealer_KY_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 8e 0c 08 8d ?? ?? ?? 01 0b 16 0a 16 08 2f ?? 07 06 03 06 03 8e 5d 91 02 06 91 61 9c 06 17 58 0a 06 02 8e 32 } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}