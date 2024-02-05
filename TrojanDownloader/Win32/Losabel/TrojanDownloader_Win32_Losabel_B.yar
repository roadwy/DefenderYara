
rule TrojanDownloader_Win32_Losabel_B{
	meta:
		description = "TrojanDownloader:Win32/Losabel.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 e4 33 c0 89 45 e8 89 45 e4 89 45 ec b8 90 01 04 e8 90 01 02 ff ff 33 c0 55 68 90 01 04 64 ff 30 64 89 20 e8 90 01 02 ff ff e8 90 01 02 ff ff 3c 01 75 90 01 01 e8 90 01 02 ff ff c7 05 90 01 04 02 00 00 00 8d 45 ec e8 90 01 02 ff ff 8b 55 ec b8 90 01 04 e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff 83 3d 90 01 04 03 75 90 01 01 e8 90 01 02 ff ff 68 58 1b 00 00 e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff 6a ff 8d 45 e8 b9 90 01 04 8b 15 90 01 04 e8 90 01 02 ff ff 8b 45 e8 e8 90 01 02 ff ff 50 8d 55 e4 33 c0 e8 90 01 02 ff ff 8b 45 e4 e8 90 01 02 ff ff 50 e8 90 01 02 ff ff 68 88 13 00 00 e8 90 01 02 ff ff 33 c0 5a 59 59 90 00 } //01 00 
		$a_02_1 = {8d 45 fc 50 68 90 01 04 68 02 00 00 80 e8 90 01 02 ff ff 8d 45 fc 50 68 90 01 04 8b 45 fc 50 e8 90 01 02 ff ff 8d 45 fc 50 68 90 01 04 8b 45 fc 50 e8 90 01 02 ff ff 8d 45 f8 b9 90 01 04 8b 15 90 01 04 e8 90 01 02 ff ff 8b 45 f8 e8 90 01 02 ff ff 68 ff 00 00 00 50 6a 01 6a 00 68 90 01 04 8b 45 fc 50 e8 90 01 02 ff ff 33 c0 5a 59 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}