
rule TrojanDownloader_MacOS_Adload_S_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.S!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4b 8b 7c f5 00 48 85 ff 74 ?? 48 89 de ff 15 a5 21 00 00 49 ff c6 45 39 f4 75 ?? 4c 03 7d c0 48 8b 45 b8 4e ?? ?? ?? ?? 48 8b 45 b0 } //1
		$a_03_1 = {48 03 5d b8 41 bf 01 00 00 00 45 31 f6 49 c1 e6 04 48 8b 45 80 4a 8b 3c 30 48 89 de e8 d2 1c 00 00 85 c0 74 ?? 45 89 fe 41 ff c7 4d 39 ee } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}