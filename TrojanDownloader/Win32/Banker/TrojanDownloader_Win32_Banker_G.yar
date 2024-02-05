
rule TrojanDownloader_Win32_Banker_G{
	meta:
		description = "TrojanDownloader:Win32/Banker.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 c7 85 1c ff ff ff 01 00 00 00 c7 85 14 ff ff ff 02 00 00 00 ff d7 8b d0 8d 4d b8 ff d6 8d 55 84 8d 45 dc 8d 4d 94 52 50 c7 45 8c 04 00 00 00 c7 45 84 02 00 00 00 89 8d 1c ff ff ff c7 85 14 ff ff ff 08 40 00 00 } //01 00 
		$a_02_1 = {8d 95 54 ff ff ff 51 52 ff d7 50 8d 85 44 ff ff ff 8d 8d 34 ff ff ff 50 51 ff d7 8d 95 24 ff ff ff 50 52 ff 15 90 01 02 40 00 8b d0 8d 4d a8 ff d6 8d 85 34 ff ff ff 90 00 } //01 00 
		$a_00_2 = {07 00 00 00 75 72 6c 6d 6f 6e 00 00 13 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}