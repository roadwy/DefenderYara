
rule TrojanDownloader_Win32_Banload_AJH{
	meta:
		description = "TrojanDownloader:Win32/Banload.AJH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f } //05 00 
		$a_03_1 = {8b d8 85 db 7e 2c e8 90 01 03 ff b8 90 01 01 00 00 00 e8 90 01 03 ff ba 90 01 04 8a 14 02 8d 45 fc e8 90 01 03 ff 8b 55 fc 8b c6 e8 90 01 03 ff 4b 75 d4 33 c0 5a 90 00 } //02 00 
		$a_03_2 = {8d 55 d0 b8 06 00 00 00 e8 90 01 03 ff ff 75 d0 68 90 01 04 68 90 01 04 90 02 05 8d 45 d4 ba 90 03 01 01 03 04 00 00 00 e8 90 01 03 ff 8b 45 d4 e8 90 01 03 ff 8b d0 b8 90 01 04 e8 90 01 03 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}