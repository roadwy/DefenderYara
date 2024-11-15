
rule TrojanDownloader_MacOS_Adload_T_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.T!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 56 53 48 81 ec 30 01 00 00 31 c0 41 b8 20 00 00 00 45 89 c1 41 b8 10 00 00 00 45 89 c2 41 b8 08 00 00 00 45 89 c3 48 8d 5d e8 48 89 bd 78 ff ff ff 48 89 df 48 89 b5 70 ff ff ff 89 c6 48 89 95 68 ff ff ff 4c 89 da 4c 89 95 60 ff ff ff 48 89 8d 58 ff ff ff 4c 89 8d 50 ff ff ff 4c 89 9d 48 ff ff ff } //1
		$a_01_1 = {55 48 89 e5 41 55 48 81 ec e8 00 00 00 48 c7 45 e8 00 00 00 00 48 89 75 f0 48 8b 46 f8 48 8b 48 40 48 83 c1 0f 48 83 e1 f0 49 89 e0 49 29 c8 4c 89 c4 48 89 7d e8 48 8b 48 10 48 89 7d a0 4c 89 c7 48 89 75 98 4c 89 ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}