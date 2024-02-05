
rule TrojanDownloader_Win32_Yektel_B{
	meta:
		description = "TrojanDownloader:Win32/Yektel.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 66 81 ff 28 23 7d 52 33 c0 89 04 24 54 6a 00 55 e8 90 01 03 ff e8 90 01 03 ff 90 00 } //01 00 
		$a_03_1 = {66 ff 45 ee 66 81 7d ee 28 23 7d 69 33 c0 89 45 f4 8d 45 f4 50 6a 00 8b 45 f8 50 e8 90 01 02 ff ff e8 90 01 02 ff ff 90 00 } //02 00 
		$a_03_2 = {19 04 74 0b 66 81 3d 90 01 04 22 04 75 1f a1 90 01 04 8b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}