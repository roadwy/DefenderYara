
rule TrojanDownloader_MacOS_Adload_G_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.G!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 d2 90 41 0f b6 1c 16 88 1c 11 48 ff c2 49 39 d1 75 f0 4c 8b 65 90 4c 01 e8 eb 34 } //1
		$a_01_1 = {45 31 ff 45 31 e4 e9 88 01 00 00 90 42 0f b6 74 2b ff 48 8b 5d 98 48 8b 45 a0 48 39 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}