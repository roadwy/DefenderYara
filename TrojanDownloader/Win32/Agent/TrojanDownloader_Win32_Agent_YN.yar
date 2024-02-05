
rule TrojanDownloader_Win32_Agent_YN{
	meta:
		description = "TrojanDownloader:Win32/Agent.YN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 f4 df 6d f0 dd 5d f8 9b 8d 45 ec 50 dd 45 f8 db 7d e0 9b 8d 45 e0 89 45 f0 c6 45 f4 03 8d 55 f0 33 c9 b8 90 01 04 e8 90 00 } //01 00 
		$a_03_1 = {8a 06 8b c8 80 c1 d0 80 e9 37 73 35 8a 4e 01 80 c1 d0 80 e9 37 73 2a 25 ff 00 00 00 66 8b 04 45 90 01 04 c1 e0 04 33 c9 8a 4e 01 66 8b 0c 4d 90 01 04 02 c1 88 02 42 83 c6 02 4f 85 ff 90 00 } //01 00 
		$a_01_2 = {8b 13 8a 54 32 ff 32 55 f7 88 54 30 ff 46 4f 75 e8 8b c3 8b 55 f8 e8 } //00 00 
	condition:
		any of ($a_*)
 
}