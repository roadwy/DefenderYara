
rule TrojanDownloader_Win32_Carberp_AD{
	meta:
		description = "TrojanDownloader:Win32/Carberp.AD,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 ee 0f b6 ee 0f b6 2c ed 90 01 04 c1 e5 08 31 ee 0f b6 ef 0f b6 2c ed 90 01 04 c1 e5 18 31 ee 0f b6 ea 0f b6 2c ed 90 01 04 31 ef 0f b6 ec 0f b6 2c ed 90 01 04 c1 e5 08 31 ef 90 00 } //0a 00 
		$a_03_1 = {89 74 24 10 8b 3c d5 90 01 04 f2 ae f7 d1 2b f9 8b c1 8b f7 8b 7c 24 10 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8b 34 d5 90 01 04 c6 05 90 01 04 01 eb 45 ff d5 99 f7 3d 90 01 04 83 c9 ff 90 00 } //01 00 
		$a_03_2 = {b9 ff 09 00 00 8d 7c 24 09 f3 ab 66 ab aa 33 c0 b9 00 0a 00 00 bf 90 01 04 f3 ab b9 00 0a 00 00 8d 7c 24 08 f3 ab 8d 44 24 04 50 8d 4c 24 0c 90 00 } //01 00 
		$a_03_3 = {b9 ff 09 00 00 8d bd f9 d7 ff ff f3 ab 66 ab be 00 28 00 00 56 aa 53 bf 90 01 04 57 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}