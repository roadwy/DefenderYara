
rule TrojanDownloader_Win32_Stasky_B{
	meta:
		description = "TrojanDownloader:Win32/Stasky.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 45 f0 64 a3 00 00 00 00 89 65 e8 c7 45 fc 00 00 00 00 e4 02 c7 45 fc fe ff ff ff 32 c0 } //01 00 
		$a_01_1 = {84 c0 74 09 68 80 ee 36 00 ff d6 eb ee 68 60 ea 00 00 ff d6 eb e5 } //01 00 
		$a_03_2 = {68 00 01 00 84 56 56 50 90 01 01 e8 90 01 04 ff d0 8b 90 01 01 3b 90 01 01 74 90 01 01 8d 4d 90 01 01 51 8d 55 90 01 01 52 8d 45 90 01 01 50 68 05 00 00 20 90 00 } //01 00 
		$a_03_3 = {83 65 fc 00 e4 02 90 03 07 04 c7 45 fc fe ff ff ff 83 4d fc ff 32 c0 90 00 } //01 00 
		$a_03_4 = {84 c0 74 07 68 80 ee 36 00 eb 05 68 60 ea 00 00 90 03 02 05 ff d6 ff 15 90 01 04 eb 90 00 } //01 00 
		$a_01_5 = {c7 45 fc 00 00 00 00 e4 02 c7 45 fc fe ff ff ff 32 c0 } //00 00 
	condition:
		any of ($a_*)
 
}