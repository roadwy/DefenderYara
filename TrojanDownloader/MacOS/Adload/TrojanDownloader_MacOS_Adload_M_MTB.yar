
rule TrojanDownloader_MacOS_Adload_M_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.M!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 41 56 53 48 81 ec 20 01 00 00 49 89 fe 48 ?? ?? ?? ?? ?? ?? be 20 00 00 00 e8 ?? a3 00 00 83 f8 01 7f ?? 48 ?? ?? ?? ?? ?? ?? 31 f6 4c 89 f2 e8 c8 ab ff ff 48 89 c1 } //1
		$a_03_1 = {48 83 e7 fc 48 8b 5f 08 8b 13 83 e2 03 83 fa 01 74 ?? 48 89 04 f1 48 ff c6 4c 39 c6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}