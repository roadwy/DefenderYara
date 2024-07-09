
rule TrojanDownloader_MacOS_Adload_B_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 07 48 8b 4f 08 48 89 85 70 ff ff ff 48 89 8d 78 ff ff ff 48 8b 47 10 48 89 45 80 48 8b 85 e8 fe ff ff 48 8b 95 f0 fe ff ff 89 d1 29 c1 89 ce c1 ee 1f 01 ce d1 fe 48 63 f6 48 01 c6 e8 ?? ?? f8 ff 4c 8b 7d 90 90 48 8b 5d 98 } //1
		$a_03_1 = {66 0f 57 c0 48 8d 7d 90 90 66 0f 29 07 48 c7 47 10 00 00 00 00 48 89 de 4c 29 fe 48 03 b5 78 ff ff ff 48 2b b5 70 ff ff ff e8 ?? ?? ?? ff 48 8d 7d 90 90 48 8b 77 08 48 8b 95 70 ff ff ff 48 8b 8d 78 ff ff ff e8 ?? ?? ?? ff 4c 39 fb 74 13 48 8d 7d 90 90 48 8b 77 08 4c 89 fa 48 89 d9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}