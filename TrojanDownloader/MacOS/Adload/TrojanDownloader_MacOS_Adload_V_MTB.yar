
rule TrojanDownloader_MacOS_Adload_V_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.V!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 01 f5 44 89 6d d4 31 d2 49 89 54 24 10 49 89 54 24 08 49 89 14 24 4a 63 0c b1 8a 0c 0f 80 e1 f0 45 31 f6 80 f9 d0 41 0f 94 c6 41 ff c6 44 0f af f0 8b 4b 40 44 89 f0 0f af c1 85 c0 0f 8e f3 00 00 00 48 8d 43 18 48 89 45 98 } //1
		$a_01_1 = {89 f2 c1 e2 08 0f b6 74 08 ff 09 d6 48 ff c9 7f ef 49 8b 44 24 08 49 3b 44 24 10 4c 89 fb 73 0d 89 30 48 83 c0 04 49 89 44 24 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}