
rule TrojanDownloader_Win32_Agent_GYJ{
	meta:
		description = "TrojanDownloader:Win32/Agent.GYJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 ec 68 b9 19 00 00 00 33 c0 53 55 56 57 8d 7c 24 14 6a 64 f3 ab 8d 44 24 18 50 ff 15 80 30 40 00 bf 64 41 40 00 83 c9 ff 33 c0 8d 54 24 14 f2 ae f7 d1 2b f9 68 60 41 40 00 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 68 8b 00 00 00 83 e1 03 50 f3 a4 ff 15 7c 30 40 00 8b f0 56 6a 00 ff 15 78 30 40 00 56 6a 00 8b d8 ff 15 74 30 40 00 53 6a 40 8b f0 ff 15 48 30 40 00 56 8b e8 ff 15 1c 30 40 00 8b cb 8b f0 8b c1 8b fd c1 e9 02 f3 a5 8b c8 6a 00 83 e1 03 6a 00 f3 a4 6a 02 6a 00 6a 00 8d 4c 24 28 68 00 00 00 40 51 ff 15 20 30 40 00 } //01 00 
		$a_00_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 73 79 73 2e 62 61 74 } //01 00  C:\Program Files\sys.bat
		$a_00_2 = {26 6e 65 74 20 73 74 6f 70 20 4b 50 66 77 53 76 63 26 6e 65 74 20 73 74 6f 70 20 4b 57 61 74 63 68 73 76 63 26 6e 65 74 20 73 74 6f 70 20 4d 63 53 68 69 65 6c 64 26 6e 65 74 20 73 74 6f 70 20 22 4e 6f 72 74 6f 6e 20 41 6e 74 69 56 69 72 75 73 20 53 65 72 76 65 72 22 } //00 00  &net stop KPfwSvc&net stop KWatchsvc&net stop McShield&net stop "Norton AntiVirus Server"
	condition:
		any of ($a_*)
 
}