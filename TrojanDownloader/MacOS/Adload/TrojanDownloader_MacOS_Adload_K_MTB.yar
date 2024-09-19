
rule TrojanDownloader_MacOS_Adload_K_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d3 0f 57 c0 0f 29 85 00 ff ff ff 48 c7 85 10 ff ff ff 00 00 00 00 4c ?? ?? ?? ?? ?? ?? 31 db 4c ?? ?? ?? ?? ?? ?? 66 ?? 41 0f b6 07 0f 57 c0 0f 29 85 20 ff ff ff 48 c7 85 30 ff ff ff 00 00 00 00 c6 85 20 ff ff ff 02 } //1
		$a_03_1 = {0f b6 03 0f 57 c0 0f 29 85 20 ff ff ff 48 c7 85 30 ff ff ff 00 00 00 00 c6 85 20 ff ff ff 02 41 88 45 00 c6 85 22 ff ff ff 00 ba 01 00 00 00 4c 89 ff 4c 89 ee e8 d4 57 00 00 f6 85 20 ff ff ff 01 74 ?? 48 8b bd 30 ff ff ff e8 d1 57 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}