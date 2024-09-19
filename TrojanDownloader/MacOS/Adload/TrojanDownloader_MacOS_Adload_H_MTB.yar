
rule TrojanDownloader_MacOS_Adload_H_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.H!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 49 89 d7 ff 15 98 25 00 00 41 89 c6 85 c0 74 ?? 45 89 f4 49 c1 e4 03 31 db 49 8b 3c 1f e8 a8 0e 00 00 48 83 c3 08 49 39 dc } //1
		$a_03_1 = {41 83 e7 0f 74 ?? 48 89 55 c0 48 89 4d b8 48 89 45 b0 48 8b 1d 42 26 00 00 41 ff cf 41 83 e4 0f 45 31 f6 4b 8b 7c f5 00 48 85 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}