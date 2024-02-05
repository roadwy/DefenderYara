
rule TrojanDownloader_Win32_Leckbrio_B{
	meta:
		description = "TrojanDownloader:Win32/Leckbrio.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 89 03 b8 1d 00 00 00 e8 90 01 04 40 ba 90 01 04 8a 44 02 ff 8b 13 88 82 90 01 04 ff 03 83 3b 1f 75 dd 90 00 } //01 00 
		$a_03_1 = {b8 3a 00 00 00 e8 90 01 04 ff b5 90 01 02 ff ff 8d 95 90 01 02 ff ff b8 2a 00 00 00 e8 90 01 04 ff b5 90 01 02 ff ff 8d 95 90 01 02 ff ff b8 3a 90 00 } //01 00 
		$a_03_2 = {80 3b 4d 0f 85 90 01 04 6a 00 6a 00 6a 01 6a 00 6a 00 68 00 00 00 40 8b 45 e0 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}