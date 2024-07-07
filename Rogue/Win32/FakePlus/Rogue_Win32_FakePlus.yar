
rule Rogue_Win32_FakePlus{
	meta:
		description = "Rogue:Win32/FakePlus,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {53 75 70 65 72 4d 65 67 61 46 6f 72 63 65 } //1 SuperMegaForce
		$a_03_2 = {54 6a 06 68 90 01 04 a1 90 01 04 50 6a ff e8 90 01 04 c6 05 90 01 04 68 c7 05 90 01 08 c6 05 90 01 04 c3 54 6a 06 68 90 01 04 a1 90 01 04 50 6a ff e8 90 00 } //5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*5) >=6
 
}
rule Rogue_Win32_FakePlus_2{
	meta:
		description = "Rogue:Win32/FakePlus,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {54 54 49 45 41 64 76 42 48 4f } //1 TTIEAdvBHO
		$a_00_1 = {61 6e 74 69 76 69 72 75 73 70 6c 75 73 32 30 30 39 2e 63 6f 6d } //2 antivirusplus2009.com
		$a_00_2 = {61 6e 74 69 76 69 72 75 73 2d 70 6c 75 73 2d 32 30 30 39 2e 63 6f 6d } //2 antivirus-plus-2009.com
		$a_00_3 = {73 65 63 75 72 65 2d 70 6c 75 73 2d 70 61 79 6d 65 6e 74 73 2e 63 6f 6d } //2 secure-plus-payments.com
		$a_00_4 = {49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 } //5
		$a_01_5 = {3f 75 72 6c 3d 00 00 00 ff ff ff ff 04 00 00 00 26 69 64 3d 00 } //6
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*5+(#a_01_5  & 1)*6) >=8
 
}
rule Rogue_Win32_FakePlus_3{
	meta:
		description = "Rogue:Win32/FakePlus,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {51 68 e2 00 00 00 57 56 ff 15 90 01 04 85 c0 74 19 81 7c 24 08 e2 00 00 00 75 0f 90 00 } //2
		$a_03_1 = {30 1c 01 42 3b d7 7c 02 33 d2 41 81 f9 90 01 02 00 00 7c 90 00 } //2
		$a_00_2 = {75 00 69 00 64 00 3d 00 25 00 73 00 26 00 76 00 3d 00 25 00 75 00 26 00 61 00 69 00 64 00 3d 00 25 00 73 00 } //1 uid=%s&v=%u&aid=%s
		$a_00_3 = {25 00 73 00 25 00 73 00 3f 00 75 00 72 00 6c 00 3d 00 25 00 73 00 26 00 69 00 64 00 3d 00 25 00 73 00 } //1 %s%s?url=%s&id=%s
		$a_00_4 = {65 00 78 00 65 00 5f 00 69 00 6e 00 5f 00 64 00 62 00 2e 00 70 00 68 00 70 00 } //1 exe_in_db.php
		$a_00_5 = {6d 00 79 00 2d 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 70 00 6c 00 75 00 73 00 2e 00 6f 00 72 00 67 00 } //1 my-antivirusplus.org
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}
rule Rogue_Win32_FakePlus_4{
	meta:
		description = "Rogue:Win32/FakePlus,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 10 00 00 "
		
	strings :
		$a_00_0 = {5c 73 79 73 74 65 6d 33 32 5c 61 76 70 2e 69 64 00 } //1
		$a_00_1 = {41 63 74 69 76 61 74 69 6e 67 2e 20 50 6c 65 61 73 65 20 57 61 69 74 2e 20 54 68 69 73 20 6d 61 79 20 74 61 6b 65 20 61 20 66 65 77 20 6d 69 6e 75 74 65 73 2e 2e 2e } //1 Activating. Please Wait. This may take a few minutes...
		$a_00_2 = {20 73 65 72 69 6f 75 73 20 74 68 72 65 61 74 73 20 61 72 65 20 66 6f 75 6e 64 20 77 68 69 6c 65 20 73 63 61 6e 6e 69 6e 67 20 79 6f 75 72 20 66 69 6c 65 73 20 61 6e 64 20 72 65 67 69 73 74 72 79 21 } //1  serious threats are found while scanning your files and registry!
		$a_00_3 = {49 74 20 69 73 20 73 74 72 6f 6e 67 6c 79 20 72 65 63 6f 6d 65 6e 64 65 64 20 74 6f 20 65 6e 74 69 72 65 6c 79 20 63 6c 65 61 6e 20 79 6f 75 72 20 50 43 20 69 6e 20 6f 72 64 65 72 20 74 6f 20 70 72 6f 74 65 63 74 20 74 68 65 20 73 79 73 74 65 6d 20 61 67 61 69 6e 73 74 20 66 75 74 75 72 65 20 69 6e 74 72 75 73 69 6f 6e 73 21 } //1 It is strongly recomended to entirely clean your PC in order to protect the system against future intrusions!
		$a_00_4 = {49 6e 66 65 63 74 73 20 65 78 65 63 75 74 61 62 6c 65 20 66 69 6c 65 73 20 77 69 74 68 20 42 53 2d 77 6f 72 6d 2c 20 63 6f 72 72 75 70 74 73 20 4d 53 20 4f 66 66 69 63 65 20 64 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 73 70 72 65 61 64 73 68 65 65 74 73 2e } //2 Infects executable files with BS-worm, corrupts MS Office documents and spreadsheets.
		$a_00_5 = {41 6e 74 69 76 69 72 75 73 20 50 6c 75 73 00 } //2
		$a_00_6 = {41 6e 74 69 76 69 72 75 73 20 50 6c 75 73 20 69 73 20 61 6c 72 65 61 64 79 20 72 75 6e 6e 69 6e 67 20 69 6e 20 73 79 73 74 65 6d 20 74 72 61 79 2e } //2 Antivirus Plus is already running in system tray.
		$a_00_7 = {59 6f 75 72 20 63 6f 6f 6b 69 65 73 20 61 6e 64 20 74 65 6d 70 6f 72 61 72 79 20 66 69 6c 65 73 20 77 65 72 65 20 64 65 6c 65 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 } //2 Your cookies and temporary files were deleted successfully!
		$a_00_8 = {69 6e 73 74 61 6c 6c 2f 41 6e 74 69 76 69 72 75 73 50 6c 75 73 2e 67 72 6e } //3 install/AntivirusPlus.grn
		$a_00_9 = {63 66 67 2f 64 6d 6e 73 2e 63 66 67 } //3 cfg/dmns.cfg
		$a_00_10 = {63 62 2f 72 65 61 6c 2e 70 68 70 3f 69 64 3d 00 } //4
		$a_00_11 = {7b 44 30 33 32 35 37 30 41 2d 35 46 36 33 2d 34 38 31 32 2d 41 30 39 34 2d 38 37 44 30 30 37 43 32 33 30 31 32 7d } //3 {D032570A-5F63-4812-A094-87D007C23012}
		$a_00_12 = {57 61 72 6e 69 6e 67 21 20 00 00 00 ff ff ff ff 0f 00 00 00 20 74 68 72 65 61 74 73 20 66 6f 75 6e 64 21 } //3
		$a_00_13 = {52 65 67 75 6c 61 72 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 20 75 70 64 61 74 65 73 20 61 72 65 20 6e 65 63 65 73 73 61 72 79 } //1 Regular antivirus software updates are necessary
		$a_03_14 = {6a 01 6a 00 6a 02 6a 00 6a ff e8 90 01 04 8b d8 e8 90 01 04 3d b7 00 00 00 75 1b 68 10 00 04 00 68 90 01 04 68 90 01 04 6a 00 e8 90 00 } //6
		$a_00_15 = {69 6e 73 74 61 6c 6c 2f 61 76 70 6c 75 73 2e 64 6c 6c 00 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*3+(#a_00_9  & 1)*3+(#a_00_10  & 1)*4+(#a_00_11  & 1)*3+(#a_00_12  & 1)*3+(#a_00_13  & 1)*1+(#a_03_14  & 1)*6+(#a_00_15  & 1)*3) >=7
 
}
rule Rogue_Win32_FakePlus_5{
	meta:
		description = "Rogue:Win32/FakePlus,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 35 44 21 41 00 56 ff 75 fc e8 53 bc ff ff 4f 75 ee 8b 4d fc 8d 81 b4 15 00 00 81 c1 64 31 00 00 33 08 6a 43 81 f1 87 d2 e3 f3 89 08 5f } //1
		$a_01_1 = {a3 34 1d 41 00 8b 45 0c ff 30 e8 28 0a 00 00 33 06 5f 35 d7 d5 e3 e3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Rogue_Win32_FakePlus_6{
	meta:
		description = "Rogue:Win32/FakePlus,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 69 64 3d 25 73 26 76 3d 25 75 26 61 69 64 3d 25 73 } //2 uid=%s&v=%u&aid=%s
		$a_01_1 = {2f 63 62 2f 65 78 65 5f 69 6e 5f 64 62 2e 70 68 70 } //2 /cb/exe_in_db.php
		$a_01_2 = {2f 63 6d 64 2e 70 68 70 } //1 /cmd.php
		$a_01_3 = {41 56 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 } //1 AVDownloadAndExecuteCommand
		$a_01_4 = {75 69 64 5f 6d 75 74 61 6e 74 00 } //2
		$a_01_5 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=5
 
}