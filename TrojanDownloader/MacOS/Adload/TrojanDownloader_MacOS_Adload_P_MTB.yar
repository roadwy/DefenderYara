
rule TrojanDownloader_MacOS_Adload_P_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.P!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 89 d6 48 89 c3 48 8d 7d e0 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 41 83 fe 02 75 ?? 48 8b 38 } //1
		$a_03_1 = {4d 8b 6e 60 4b 8b 7c 3d f0 e8 ?? ?? ?? ?? 4b 8b 4c 3d f8 4b 8b 54 3d 00 4c 89 e7 48 89 c6 e8 ?? ?? ?? ?? 48 ff c3 49 63 46 68 49 83 c7 18 48 39 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}