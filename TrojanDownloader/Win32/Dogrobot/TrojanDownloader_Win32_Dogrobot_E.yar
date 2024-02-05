
rule TrojanDownloader_Win32_Dogrobot_E{
	meta:
		description = "TrojanDownloader:Win32/Dogrobot.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 75 08 b8 03 00 00 00 8b 4d 0c 31 06 46 e2 fb 8b fa 83 c9 ff 33 c0 8b 5d 10 } //01 00 
		$a_03_1 = {6a 00 8d 54 24 18 68 04 01 00 00 52 57 56 ff 15 90 01 04 85 c0 75 0c 90 00 } //01 00 
		$a_01_2 = {63 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d } //01 00 
		$a_01_3 = {8b 44 24 10 80 3e 00 75 02 8b f5 8a 0e 8a 10 2a d1 88 10 8a ca 8a 16 32 d1 46 88 10 40 4f 75 e4 } //01 00 
		$a_01_4 = {25 73 5c 25 64 5f 78 65 65 78 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}