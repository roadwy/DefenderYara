
rule TrojanDownloader_Win32_Chopanez_A{
	meta:
		description = "TrojanDownloader:Win32/Chopanez.A,SIGNATURE_TYPE_PEHSTR_EXT,19 00 14 00 10 00 00 05 00 "
		
	strings :
		$a_00_0 = {73 79 73 74 65 6d 33 32 5f 78 70 5f 73 79 73 74 65 6d 5f 6e 65 77 } //05 00  system32_xp_system_new
		$a_00_1 = {66 75 63 6b 20 6f 66 66 2c 20 62 75 64 64 79 } //05 00  fuck off, buddy
		$a_00_2 = {63 3a 5c 5f 68 61 6c 74 } //05 00  c:\_halt
		$a_00_3 = {43 3a 5c 54 45 4d 50 69 6e 65 74 32 30 30 } //05 00  C:\TEMPinet200
		$a_00_4 = {31 32 37 2e 30 2e 30 2e 31 20 64 6f 77 6e 6c 6f 61 64 2e 6d 63 61 66 65 65 2e 63 6f 6d 20 6c 69 76 65 75 70 64 61 74 65 2e 73 79 6d 61 6e 74 65 63 6c 69 76 65 75 70 64 61 74 65 2e 63 6f 6d 20 6c 69 76 65 75 70 64 61 74 65 2e 73 79 6d 61 6e 74 65 63 2e 63 6f 6d 20 75 70 64 61 74 65 2e 73 79 6d 61 6e 74 65 63 2e 63 6f 6d } //02 00  127.0.0.1 download.mcafee.com liveupdate.symantecliveupdate.com liveupdate.symantec.com update.symantec.com
		$a_00_5 = {43 3a 5c 77 65 62 2e 65 78 65 } //02 00  C:\web.exe
		$a_02_6 = {83 c5 74 c9 c3 56 57 e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff be 90 01 02 40 00 56 33 ff e8 90 01 02 ff ff 85 c0 59 75 7c 53 e8 90 01 02 ff ff 6a 3c 33 d2 8b c7 59 f7 f1 85 d2 75 41 ff 35 90 01 02 40 00 e8 90 01 02 ff ff 85 c0 59 75 31 ff 35 90 01 02 40 00 e8 90 01 02 ff ff 85 c0 59 75 21 ff 35 90 01 02 40 00 e8 90 01 02 ff ff 90 00 } //02 00 
		$a_02_7 = {53 b8 01 00 00 00 0f a2 f7 c2 00 00 80 00 0f 95 c0 0f b6 c0 a3 90 01 02 40 00 5b c3 90 00 } //02 00 
		$a_02_8 = {55 8b ec 83 ec 08 e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 68 90 01 02 40 00 e8 90 01 02 ff ff 83 c4 04 85 c0 74 05 e9 90 01 02 00 00 e8 90 01 02 ff ff 8b 45 fc 33 d2 b9 3c 00 00 00 f7 f1 90 00 } //02 00 
		$a_02_9 = {55 8b ec 53 b8 01 00 00 00 0f a2 f7 c2 00 00 80 00 0f 95 c0 0f b6 c0 a3 90 01 02 40 00 5b 5d c3 90 00 } //01 00 
		$a_00_10 = {2f 61 66 66 69 6c 69 61 74 65 2f 69 6e 74 65 72 66 61 63 65 2e 70 68 70 3f 75 73 65 72 69 64 3d } //01 00  /affiliate/interface.php?userid=
		$a_00_11 = {26 70 72 6f 67 72 61 6d 3d 37 26 76 61 72 69 61 62 6c 65 3d 63 68 65 63 6b 26 76 61 6c 75 65 3d } //02 00  &program=7&variable=check&value=
		$a_00_12 = {72 78 73 2e 69 6e 69 2e 70 68 70 } //01 00  rxs.ini.php
		$a_00_13 = {2f 61 66 66 63 67 69 2f 6f 6e 6c 69 6e 65 2e 66 63 67 69 3f 25 41 43 43 4f 55 4e 54 25 } //01 00  /affcgi/online.fcgi?%ACCOUNT%
		$a_00_14 = {2f 6d 6d 2e 65 78 65 20 6d 6d 78 } //01 00  /mm.exe mmx
		$a_00_15 = {2f 6d 6d 32 2e 65 78 65 20 6d 6d 32 2e 65 78 65 20 25 41 43 43 4f 55 4e 54 25 } //00 00  /mm2.exe mm2.exe %ACCOUNT%
	condition:
		any of ($a_*)
 
}