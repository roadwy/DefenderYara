
rule TrojanDownloader_MacOS_Adload_L_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.L!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 c6 04 2c 00 4d 8b 7e 10 66 0f ef c0 66 0f 7f 85 a0 fc ff ff 48 c7 85 b0 fc ff ff 00 00 00 00 4c 89 ff e8 52 4b 00 00 48 83 f8 f0 0f ?? ?? ?? ?? ?? 49 89 c5 48 83 f8 17 73 ?? 44 89 e8 44 00 e8 88 85 a0 fc ff ff } //1
		$a_03_1 = {45 31 e4 45 31 ed e9 ?? ?? ?? ?? 0f 1f 84 00 00 00 00 00 4c 39 f1 0f ?? ?? ?? ?? ?? 46 0f b6 7c 37 ff 42 8b 04 37 44 01 c0 41 28 c7 48 8b 9d 08 ff ff ff 48 8b 85 10 ff ff ff 48 39 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}