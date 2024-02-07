
rule TrojanDownloader_Win32_Wesoten_A{
	meta:
		description = "TrojanDownloader:Win32/Wesoten.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 75 fc bf 04 01 00 00 57 8d 85 a4 fc ff ff 50 ff 15 90 01 04 68 98 05 40 00 8d 85 a4 fc ff ff 50 ff 15 90 01 04 57 8d 85 b0 fd ff ff 50 56 8b 1d 90 00 } //01 00 
		$a_03_1 = {8d 85 1c f8 ff ff 50 ff 15 90 01 02 40 00 68 20 bf 02 00 ff 15 90 01 02 40 00 e9 b7 fd ff ff 83 a5 94 f6 ff ff 00 80 a5 d4 f6 ff ff 00 33 c0 8d bd d5 f6 ff ff ab 90 00 } //01 00 
		$a_03_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 90 02 40 63 6d 64 20 2f 63 20 73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30 90 00 } //01 00 
		$a_01_3 = {25 30 34 64 25 30 32 64 25 30 32 64 } //00 00  %04d%02d%02d
	condition:
		any of ($a_*)
 
}