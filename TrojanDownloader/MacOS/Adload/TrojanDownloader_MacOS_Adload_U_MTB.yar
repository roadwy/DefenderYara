
rule TrojanDownloader_MacOS_Adload_U_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.U!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 53 50 48 8b 35 66 24 00 00 48 8b 1d a7 20 00 00 ff d3 48 8b 35 66 24 00 00 48 89 c7 48 89 d8 48 83 c4 08 5b 5d ff e0 } //1
		$a_03_1 = {49 89 d7 ff 15 c0 24 00 00 41 89 c6 85 c0 74 ?? 45 89 f4 49 c1 e4 03 31 db 49 8b 3c 1f e8 a8 0e 00 00 48 83 c3 08 49 39 dc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}