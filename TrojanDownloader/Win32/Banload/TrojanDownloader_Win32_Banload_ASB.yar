
rule TrojanDownloader_Win32_Banload_ASB{
	meta:
		description = "TrojanDownloader:Win32/Banload.ASB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 2f bf 01 00 00 00 8b c3 34 01 84 c0 74 1b 8d 45 f0 8b 55 fc 0f b6 54 3a ff e8 90 01 03 ff 8b 55 f0 8d 45 f8 e8 90 01 03 ff 80 f3 01 47 90 00 } //01 00 
		$a_03_1 = {8d 45 f4 50 68 00 10 00 00 8d 85 e6 ef ff ff 50 53 e8 90 01 04 85 c0 74 26 83 7d f4 00 76 1a 81 7d f4 00 10 00 00 77 11 8d 95 e6 ef ff ff 8b 4d f4 8b 45 f8 8b 30 90 00 } //01 00 
		$a_01_2 = {83 e8 04 8b 00 83 f8 01 7c 13 8b 55 fc 80 7c 02 ff 2f 75 04 8b d8 eb } //01 00 
		$a_00_3 = {6d 61 64 53 65 63 75 72 69 74 79 55 } //00 00  madSecurityU
	condition:
		any of ($a_*)
 
}