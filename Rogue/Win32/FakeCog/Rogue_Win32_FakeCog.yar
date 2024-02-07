
rule Rogue_Win32_FakeCog{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 4c 6a 00 51 6a 01 6a 04 ff 15 90 01 04 6a 00 ff d6 50 90 00 } //02 00 
		$a_01_1 = {7e 0c 80 7c 0c 18 5c 74 05 49 85 c9 7f f4 8b 94 24 20 11 00 00 8d 44 0c 19 } //01 00 
		$a_01_2 = {63 6f 72 65 67 75 61 72 64 } //00 00  coreguard
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_2{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {b8 47 39 00 00 8b 4a 1c eb 1a 8b 54 24 64 b8 07 11 00 00 8b 4a 20 eb 0c } //02 00 
		$a_01_1 = {6d 61 6b 65 20 79 6f 75 72 20 50 43 20 66 75 6c 6c 20 73 63 61 6e 6e 69 6e 67 2e 3c 2f 62 72 } //01 00  make your PC full scanning.</br
		$a_03_2 = {d8 3d 87 88 90 09 0a 00 3f 00 00 00 3f 08 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_3{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {5f 66 61 76 64 61 74 61 2e 64 61 74 00 00 00 00 76 65 72 00 73 75 62 69 64 00 00 00 61 66 66 69 64 00 } //01 00 
		$a_01_1 = {55 73 65 72 20 50 72 6f 74 65 63 74 69 6f 6e 20 53 75 70 70 6f 72 74 2e 6c 6e 6b } //01 00  User Protection Support.lnk
		$a_01_2 = {75 73 72 65 78 74 2e 64 6c 6c 00 } //01 00 
		$a_01_3 = {75 73 72 70 72 6f 74 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_4{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 00 53 00 5c 00 25 00 53 00 2e 00 6c 00 6e 00 6b 00 00 00 90 02 40 25 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 90 00 } //01 00 
		$a_00_1 = {53 69 6e 67 6c 65 20 55 73 65 72 20 4c 69 63 65 6e 73 65 20 47 72 61 6e 74 3a 20 47 75 61 72 64 53 6f 66 74 2c 20 4c 74 64 2e 20 28 22 47 75 61 72 64 53 6f 66 74 22 29 } //00 00  Single User License Grant: GuardSoft, Ltd. ("GuardSoft")
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_5{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 04 00 "
		
	strings :
		$a_03_0 = {33 c0 8b 44 24 0c be 90 01 04 b9 0f 00 00 00 f3 a6 74 07 83 c2 01 90 00 } //01 00 
		$a_01_1 = {50 61 6c 61 64 69 6e 20 41 6e 74 69 76 69 72 75 73 00 } //01 00 
		$a_01_2 = {4d 61 6c 77 61 72 65 20 44 65 66 65 6e 73 65 00 } //01 00 
		$a_01_3 = {44 72 2e 20 47 75 61 72 64 00 } //02 00 
		$a_01_4 = {39 34 38 30 34 38 36 30 31 34 33 36 } //01 00  948048601436
		$a_03_5 = {20 50 72 6f 74 65 63 74 69 6f 6e 00 90 03 08 0b 90 09 10 00 59 6f 75 72 90 09 13 00 44 69 67 69 74 61 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_6{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 34 38 30 34 38 36 30 31 34 33 36 } //01 00  948048601436
		$a_00_1 = {65 3a 5c 57 6f 72 6b 69 6e 67 20 43 6f 70 69 65 73 5c 42 75 6e 64 6c 65 73 5c 44 65 66 65 6e 73 65 20 43 65 6e 74 65 72 } //01 00  e:\Working Copies\Bundles\Defense Center
		$a_00_2 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 00 00 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00 00 00 63 00 6f 00 64 00 65 00 63 00 70 00 61 00 63 00 6b 00 2e 00 65 00 78 00 65 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_7{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 2c 20 6d 61 72 6b 20 74 68 65 20 72 65 61 73 6f 6e 20 66 6f 72 20 72 65 6d 6f 76 65 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 21 } //01 00  Please, mark the reason for remove antivirus software!
		$a_01_1 = {5f 66 61 76 64 61 74 61 2e 64 61 74 00 00 00 00 76 65 72 00 73 75 62 69 64 00 00 00 61 66 66 69 64 00 } //01 00 
		$a_03_2 = {00 66 69 72 65 77 61 6c 6c 2e 64 6c 6c 00 90 02 0a 65 78 74 2e 64 6c 6c 00 90 05 03 01 00 55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_8{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {32 34 64 31 63 61 39 61 2d 61 38 36 34 2d 34 66 37 62 2d 38 36 66 65 2d 34 39 35 65 62 35 36 35 32 39 64 38 } //01 00  24d1ca9a-a864-4f7b-86fe-495eb56529d8
		$a_00_1 = {70 00 75 00 74 00 65 00 72 00 20 00 61 00 72 00 65 00 20 00 64 00 61 00 6d 00 61 00 67 00 65 00 64 00 2e 00 20 00 50 00 6c 00 65 00 61 00 73 00 65 00 2c 00 20 00 72 00 65 00 } //01 00  puter are damaged. Please, re
		$a_01_2 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 41 6c 65 72 74 } //01 00  Windows Security Alert
		$a_01_3 = {5c 5f 66 61 76 64 61 74 61 2e 64 61 74 } //00 00  \_favdata.dat
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_9{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 f2 03 00 00 8b ce e8 90 01 04 8b c8 e8 90 01 04 68 8c 00 00 00 90 00 } //02 00 
		$a_03_1 = {8b 75 fc 57 68 f0 03 00 00 8b ce e8 90 01 04 8b c8 e8 90 01 04 e8 90 01 04 85 c0 74 18 68 90 01 04 68 f3 03 00 00 90 00 } //01 00 
		$a_01_2 = {72 00 65 00 73 00 3a 00 2f 00 2f 00 72 00 65 00 73 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 } //01 00  res://resdll.dll
		$a_01_3 = {41 00 74 00 74 00 61 00 63 00 6b 00 73 00 20 00 70 00 6f 00 72 00 6e 00 20 00 73 00 69 00 74 00 65 00 73 00 } //01 00  Attacks porn sites
		$a_01_4 = {63 67 75 70 64 61 74 65 } //00 00  cgupdate
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_10{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 74 00 74 00 61 00 63 00 6b 00 73 00 20 00 70 00 6f 00 72 00 6e 00 20 00 73 00 69 00 74 00 65 00 73 00 } //01 00  Attacks porn sites
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 41 63 74 69 76 65 20 53 65 63 75 72 69 74 79 } //01 00  Software\Active Security
		$a_01_2 = {63 67 75 70 64 61 74 65 } //01 00  cgupdate
		$a_00_3 = {63 6f 72 65 67 75 61 72 64 00 } //01 00  潣敲畧牡d
		$a_00_4 = {7c 00 45 00 58 00 45 00 50 00 41 00 54 00 48 00 7c 00 } //01 00  |EXEPATH|
		$a_00_5 = {4d 00 69 00 64 00 64 00 6c 00 65 00 20 00 52 00 69 00 73 00 6b 00 00 00 48 00 69 00 67 00 68 00 20 00 52 00 69 00 73 00 6b 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_11{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {43 6f 72 65 47 75 61 72 64 20 41 6e 74 69 76 69 72 75 73 } //02 00  CoreGuard Antivirus
		$a_00_1 = {53 63 61 6e 20 69 74 65 6d 73 20 77 69 74 68 20 } //02 00  Scan items with 
		$a_00_2 = {53 63 61 6e 20 77 69 74 68 20 } //01 00  Scan with 
		$a_00_3 = {35 45 32 31 32 31 45 45 2d 30 33 30 30 2d 31 31 44 34 2d 38 44 33 42 2d 34 34 34 35 35 33 35 34 30 30 30 30 } //01 00  5E2121EE-0300-11D4-8D3B-444553540000
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 20 45 78 74 65 6e 73 69 6f 6e 73 5c 41 70 70 72 6f 76 65 64 } //01 00  Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
		$a_03_5 = {83 38 64 75 08 8b 45 90 01 01 83 c0 1c eb 06 8b 45 90 01 01 83 c0 24 90 00 } //02 00 
		$a_01_6 = {44 65 66 65 6e 73 65 20 43 65 6e 74 65 72 20 65 78 74 65 6e 73 69 6f 6e } //00 00  Defense Center extension
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_12{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {f6 c4 05 7b 12 8b 90 01 01 ec 8b 90 01 01 90 03 01 01 bc c0 3b 90 01 01 90 03 01 02 88 90 90 00 00 00 0f 8e 90 01 02 00 00 6a 00 90 00 } //01 00 
		$a_01_1 = {53 00 65 00 63 00 53 00 74 00 61 00 74 00 75 00 73 00 5f 00 } //01 00  SecStatus_
		$a_01_2 = {66 00 75 00 6c 00 6c 00 20 00 66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //01 00  full functional version
		$a_01_3 = {74 00 68 00 65 00 20 00 74 00 6f 00 6f 00 6c 00 73 00 20 00 6d 00 61 00 72 00 6b 00 65 00 64 00 20 00 67 00 72 00 65 00 65 00 6e 00 } //01 00  the tools marked green
		$a_01_4 = {50 00 6c 00 65 00 61 00 73 00 65 00 2c 00 20 00 6d 00 61 00 6b 00 65 00 20 00 66 00 75 00 6c 00 6c 00 20 00 63 00 68 00 65 00 63 00 6b 00 69 00 6e 00 67 00 } //01 00  Please, make full checking
		$a_01_5 = {48 4f 54 53 50 4f 54 3d } //01 00  HOTSPOT=
		$a_01_6 = {25 73 2f 63 6f 72 65 2e 63 67 61 } //00 00  %s/core.cga
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_13{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 34 38 30 34 38 36 30 31 34 33 36 } //01 00  948048601436
		$a_80_1 = {2f 72 65 61 64 64 61 74 61 67 61 74 65 77 61 79 2e 70 68 70 } ///readdatagateway.php  01 00 
		$a_80_2 = {63 6f 6d 70 75 74 65 72 20 61 72 65 20 64 61 6d 61 67 65 64 } //computer are damaged  01 00 
		$a_01_3 = {7c 54 45 58 54 58 50 7c } //01 00  |TEXTXP|
		$a_01_4 = {7c 45 58 45 50 41 54 48 7c } //01 00  |EXEPATH|
		$a_80_5 = {61 62 6f 75 74 3a 62 75 79 } //about:buy  01 00 
		$a_01_6 = {5f 66 61 76 64 61 74 61 2e 64 61 74 } //01 00  _favdata.dat
		$a_01_7 = {73 00 70 00 61 00 6d 00 30 00 30 00 31 00 2e 00 65 00 78 00 65 00 } //01 00  spam001.exe
		$a_01_8 = {61 6e 20 69 6e 63 6f 72 72 65 63 74 20 74 75 72 6e 20 6f 66 66 } //02 00  an incorrect turn off
		$a_01_9 = {83 c6 04 83 fe 0c 7c 95 5f } //01 00 
		$a_01_10 = {33 45 10 ff 45 fc 66 89 06 46 46 ff d7 39 45 fc 7c e6 } //02 00 
		$a_00_11 = {64 38 62 62 35 39 31 30 2d 32 64 38 35 2d 34 38 39 62 2d 38 34 30 33 2d 38 30 33 65 64 32 35 65 37 33 62 63 } //01 00  d8bb5910-2d85-489b-8403-803ed25e73bc
		$a_00_12 = {68 74 74 70 3a 2f 2f 25 73 2f 61 6e 79 32 2f 25 73 2d 64 69 72 65 63 74 2e 65 78 } //00 00  http://%s/any2/%s-direct.ex
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_14{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 72 65 67 75 61 72 64 } //01 00  coreguard
		$a_01_1 = {25 73 2f 62 75 79 2e 70 68 70 3f 69 64 3d 25 73 26 73 75 62 69 64 3d 25 73 } //01 00  %s/buy.php?id=%s&subid=%s
		$a_01_2 = {74 38 52 42 74 56 52 30 66 31 74 51 71 39 72 61 } //01 00  t8RBtVR0f1tQq9ra
		$a_01_3 = {34 6f 74 6a 65 73 6a 74 79 2e 6d 6f 66 } //01 00  4otjesjty.mof
		$a_01_4 = {2f 72 65 61 64 64 61 74 61 67 61 74 65 77 61 79 2e 70 68 70 } //01 00  /readdatagateway.php
		$a_01_5 = {74 68 61 74 20 73 74 65 61 6c 73 20 79 6f 75 72 20 70 61 73 73 } //01 00  that steals your pass
		$a_01_6 = {53 65 63 53 74 61 74 75 73 5f } //01 00  SecStatus_
		$a_01_7 = {75 6e 61 75 74 68 6f 72 69 7a 65 64 20 61 6e 74 69 76 69 72 75 73 } //01 00  unauthorized antivirus
		$a_01_8 = {73 63 61 6e 2e 69 63 6f } //01 00  scan.ico
		$a_01_9 = {42 75 79 2e 6c 6e 6b } //01 00  Buy.lnk
		$a_01_10 = {62 75 79 2e 69 63 6f } //01 00  buy.ico
		$a_01_11 = {50 72 6f 74 65 63 74 69 6f 6e 5c 41 62 6f 75 74 2e 6c 6e 6b } //01 00  Protection\About.lnk
		$a_01_12 = {8a 1c 29 32 d8 8b 02 2b 44 24 1c 83 f8 01 77 06 } //01 00 
		$a_01_13 = {76 22 8a 04 1f 8d 4d e0 32 45 10 88 45 } //01 00 
		$a_00_14 = {39 34 38 30 34 38 36 30 31 34 33 36 } //00 00  948048601436
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_15{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {25 73 2f 72 65 61 64 64 61 74 61 67 61 74 65 77 61 79 2e 70 68 70 3f 74 79 70 65 3d 73 74 61 74 73 26 61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d 25 73 26 75 6e 69 6e 73 74 61 6c 6c 26 76 65 72 73 69 6f 6e 3d 25 73 } //02 00  %s/readdatagateway.php?type=stats&affid=%s&subid=%s&uninstall&version=%s
		$a_01_1 = {43 6f 72 65 45 78 74 2e 64 6c 6c 00 } //02 00 
		$a_01_2 = {25 73 2f 65 6d 61 69 6c 2d 73 75 70 70 6f 72 74 2f 65 73 75 62 6d 69 74 2e 70 68 70 3f 6e 61 6d 65 3d 64 65 6c 65 74 65 26 65 6d 61 69 6c 3d } //02 00  %s/email-support/esubmit.php?name=delete&email=
		$a_01_3 = {50 6c 65 61 73 65 2c 20 6d 61 72 6b 20 74 68 65 20 72 65 61 73 6f 6e 20 66 6f 72 20 72 65 6d 6f 76 65 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 21 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_16{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 79 70 65 3d 73 74 61 74 73 26 61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d 25 73 26 69 6e 73 74 61 6c 6c 72 75 6e 73 } //02 00  type=stats&affid=%s&subid=%s&installruns
		$a_01_1 = {75 6e 61 75 74 68 6f 72 69 7a 65 64 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 20 64 65 74 65 63 74 65 64 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 2e } //02 00  unauthorized antivirus software detected on your computer.
		$a_01_2 = {55 6e 69 6e 73 74 61 6c 6c 20 43 6f 72 65 67 75 61 72 64 20 41 6e 74 69 76 69 72 75 73 20 } //01 00  Uninstall Coreguard Antivirus 
		$a_01_3 = {70 6c 75 73 5f 63 69 72 63 6c 65 2e 70 6e 67 } //01 00  plus_circle.png
		$a_01_4 = {74 69 63 6b 2e 70 6e 67 } //01 00  tick.png
		$a_01_5 = {75 6e 72 65 67 2e 68 74 6d 6c } //01 00  unreg.html
		$a_01_6 = {62 6c 61 63 6b 6c 69 73 74 2e 63 67 61 } //01 00  blacklist.cga
		$a_01_7 = {73 75 70 70 6f 72 74 2e 70 6e 67 } //00 00  support.png
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_17{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 25 00 32 00 30 00 32 00 30 00 30 00 39 00 00 00 } //02 00 
		$a_01_1 = {72 00 75 00 6e 00 3a 00 2f 00 2f 00 78 00 79 00 7a 00 00 00 } //02 00 
		$a_01_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 6e 6f 74 20 70 72 6f 74 65 63 74 65 64 20 66 72 6f 6d 20 76 69 72 75 73 20 61 74 74 61 63 6b 73 20 61 74 20 76 69 73 69 74 69 6e 67 20 70 6f 70 75 6c 61 72 20 77 65 62 73 69 74 65 73 } //01 00  Your computer is not protected from virus attacks at visiting popular websites
		$a_01_3 = {30 43 42 36 36 42 41 38 2d 35 45 31 46 2d 34 39 36 33 2d 39 33 44 31 2d 45 31 44 36 42 37 38 46 45 39 41 32 } //01 00  0CB66BA8-5E1F-4963-93D1-E1D6B78FE9A2
		$a_01_4 = {41 38 39 35 34 39 30 39 2d 31 46 30 46 2d 34 31 41 35 2d 41 37 46 41 2d 33 42 33 37 36 44 36 39 45 32 32 36 } //00 00  A8954909-1F0F-41A5-A7FA-3B376D69E226
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeCog_18{
	meta:
		description = "Rogue:Win32/FakeCog,SIGNATURE_TYPE_PEHSTR,05 00 05 00 09 00 00 03 00 "
		
	strings :
		$a_01_0 = {36 00 64 00 61 00 35 00 34 00 31 00 30 00 35 00 2d 00 31 00 34 00 36 00 65 00 2d 00 34 00 65 00 65 00 61 00 2d 00 39 00 62 00 30 00 39 00 2d 00 62 00 31 00 63 00 61 00 33 00 61 00 35 00 34 00 62 00 37 00 32 00 36 00 } //01 00  6da54105-146e-4eea-9b09-b1ca3a54b726
		$a_01_1 = {37 00 61 00 63 00 33 00 31 00 31 00 61 00 37 00 2d 00 34 00 37 00 61 00 66 00 2d 00 34 00 35 00 61 00 61 00 2d 00 39 00 35 00 61 00 34 00 2d 00 33 00 65 00 39 00 36 00 66 00 31 00 32 00 63 00 65 00 39 00 63 00 65 00 } //01 00  7ac311a7-47af-45aa-95a4-3e96f12ce9ce
		$a_01_2 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 61 00 62 00 6c 00 65 00 2e 00 2e 00 2e 00 } //01 00  Downloading antivirus executable...
		$a_01_3 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 2e 00 2e 00 } //01 00  Downloading uninstaller...
		$a_01_4 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 55 00 52 00 4c 00 20 00 62 00 6c 00 61 00 63 00 6b 00 6c 00 69 00 73 00 74 00 2e 00 2e 00 2e 00 } //01 00  Downloading URL blacklist...
		$a_01_5 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 2e 00 2e 00 2e 00 } //03 00  Downloading firewall extension...
		$a_01_6 = {25 73 2f 72 65 61 64 64 61 74 61 67 61 74 65 77 61 79 2e 70 68 70 3f 74 79 70 65 3d 73 74 61 74 73 26 61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d 25 73 26 69 6e 73 74 61 6c 6c 72 75 6e 73 26 76 65 72 73 69 6f 6e 3d 25 73 } //01 00  %s/readdatagateway.php?type=stats&affid=%s&subid=%s&installruns&version=%s
		$a_01_7 = {62 6c 61 63 6b 6c 69 73 74 2e 63 67 61 00 } //01 00 
		$a_01_8 = {63 6f 72 65 65 78 74 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}