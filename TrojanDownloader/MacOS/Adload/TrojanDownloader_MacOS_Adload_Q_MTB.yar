
rule TrojanDownloader_MacOS_Adload_Q_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.Q!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c9 31 c0 48 29 c8 48 c1 f8 03 48 b9 ab aa aa aa aa aa aa aa 48 0f af c1 66 0f ef c0 48 83 f8 01 0f ?? ?? ?? ?? ?? 66 0f 7f 85 60 fb ff ff 48 c7 85 70 fb ff ff 00 00 00 00 } //1
		$a_03_1 = {49 8b 57 08 eb ?? 66 2e 0f 1f 84 00 00 00 00 00 48 d1 ea 4c 89 f6 48 89 df e8 68 92 05 00 0f b6 85 00 ff ff ff a8 01 74 ?? 48 8b 8d 08 ff ff ff 48 85 c9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}