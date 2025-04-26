
rule TrojanDownloader_MacOS_Adload_F_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.F!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 1c 31 88 1c 32 48 ff c6 49 39 f4 75 ?? 4c 8b 65 ?? 4c 8b 4d 98 4c 01 d0 44 89 c9 44 29 e1 89 ca c1 ea 1f 01 ca d1 fa 4c 63 f2 4d 01 e6 } //1
		$a_03_1 = {4c 89 d1 48 83 e1 e0 ?? ?? ?? ?? 48 89 fe 48 c1 ee 05 48 ff c6 89 f2 83 e2 03 48 83 ff 60 0f 83 ?? ?? ?? ?? 31 ff 48 85 d2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}