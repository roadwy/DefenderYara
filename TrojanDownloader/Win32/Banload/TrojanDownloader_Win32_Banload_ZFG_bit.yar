
rule TrojanDownloader_Win32_Banload_ZFG_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZFG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 f4 e8 90 01 03 ff 8d 45 e8 50 b9 02 00 00 00 8b d6 8b c7 e8 90 01 03 ff 8b 4d e8 8d 45 ec ba 90 01 03 00 e8 90 01 03 ff 8b 45 ec e8 90 01 03 ff 8b d0 8b 45 fc 0f 90 01 03 ff 33 d0 8d 45 f0 e8 90 01 03 ff 8b 55 f0 8d 45 f4 e8 90 01 03 ff 43 83 c6 02 8b 45 fc e8 90 01 03 ff 3b d8 7e 05 90 00 } //01 00 
		$a_03_1 = {8d 4d f8 ba 90 01 03 00 b8 90 01 03 00 e8 90 01 03 ff 8b 45 f8 e8 90 01 03 ff 50 8d 4d f4 ba 90 01 03 00 b8 90 01 03 00 e8 90 01 03 ff 8b 45 f4 e8 90 01 03 ff 50 e8 90 01 03 ff 50 e8 90 01 03 ff 8b d8 6a 01 6a 00 6a 00 8b 45 fc e8 90 01 03 ff 50 68 90 01 03 00 6a 00 ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}