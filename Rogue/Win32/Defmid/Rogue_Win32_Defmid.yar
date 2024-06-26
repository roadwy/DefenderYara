
rule Rogue_Win32_Defmid{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 c0 5e c2 04 00 8b 4e 0c 6a 00 6a 00 6a 00 6a 02 6a 00 51 ff 15 90 01 04 85 c0 89 46 10 75 06 32 c0 5e c2 04 00 6a 00 6a 00 6a 00 6a 04 50 ff 15 90 01 04 89 06 b0 01 5e c2 04 00 90 00 } //01 00 
		$a_00_1 = {42 42 30 32 42 37 45 45 2d 35 46 43 32 2d 34 30 37 64 2d 41 36 45 43 2d 35 44 42 32 34 43 30 46 41 37 43 33 } //00 00  BB02B7EE-5FC2-407d-A6EC-5DB24C0FA7C3
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_Defmid_2{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 20 44 65 66 65 6e 64 65 72 20 44 6f 77 6e 6c 6f 61 64 65 72 } //01 00  System Defender Downloader
		$a_01_1 = {75 70 64 61 74 65 2e 64 61 74 } //01 00  update.dat
		$a_01_2 = {26 6c 6f 67 5f 69 64 3d } //01 00  &log_id=
		$a_01_3 = {6d 73 63 74 6c 73 5f 70 72 6f 67 72 65 73 73 33 32 } //01 00  msctls_progress32
		$a_01_4 = {49 6e 73 74 61 6c 6c 69 6e 67 20 53 79 73 74 65 6d 20 44 65 66 65 6e 64 65 72 } //01 00  Installing System Defender
		$a_01_5 = {77 6d 5f 69 64 3d } //00 00  wm_id=
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_Defmid_3{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 20 44 65 66 65 6e 64 65 72 } //01 00  System Defender
		$a_01_1 = {74 69 6d 61 6c 77 61 72 65 44 65 66 65 6e 64 65 72 5f 64 6c 6c 2e 64 6c 6c } //01 00  timalwareDefender_dll.dll
		$a_00_2 = {6e 00 64 00 65 00 72 00 5f 00 73 00 74 00 61 00 72 00 74 00 5f 00 73 00 63 00 61 00 6e 00 } //01 00  nder_start_scan
		$a_00_3 = {70 00 75 00 72 00 63 00 68 00 61 00 73 00 65 00 2f 00 67 00 65 00 74 00 2e 00 70 00 68 00 70 00 00 00 } //01 00 
		$a_00_4 = {2f 00 73 00 63 00 61 00 6e 00 5f 00 6f 00 76 00 65 00 72 00 2e 00 67 00 69 00 66 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_Defmid_4{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 00 6b 00 69 00 6e 00 2f 00 70 00 72 00 6f 00 67 00 72 00 65 00 73 00 73 00 2e 00 6a 00 73 00 } //01 00  skin/progress.js
		$a_01_1 = {43 61 6e 20 6e 6f 74 20 64 6f 77 6e 6c 6f 61 64 20 74 68 65 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 70 61 63 6b 61 67 65 2e } //01 00  Can not download the installation package.
		$a_01_2 = {4d 61 63 68 69 6e 65 47 75 69 64 00 69 6e 73 74 61 6c 6c 00 7b 00 00 00 7d 00 00 00 7b 00 00 00 7d 00 00 00 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44 } //01 00 
		$a_03_3 = {70 00 72 00 6f 00 67 00 72 00 65 00 73 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 90 02 05 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_Defmid_5{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 08 00 00 03 00 "
		
	strings :
		$a_03_0 = {68 63 2f 00 00 ff 15 90 01 04 66 89 45 90 01 01 56 6a 01 6a 02 ff 15 90 01 04 8b f8 83 ce ff 3b fe 75 90 00 } //03 00 
		$a_03_1 = {6a 03 8d 85 90 01 02 ff ff 50 6a 08 8d 4d 90 01 01 51 e8 90 01 04 8d 55 90 01 01 52 e8 90 01 04 83 c4 14 48 83 f8 04 77 90 00 } //01 00 
		$a_00_2 = {61 77 64 5f 73 74 61 72 74 5f 73 63 61 6e } //01 00  awd_start_scan
		$a_00_3 = {61 77 64 5f 73 68 6f 77 5f 73 65 63 75 72 69 74 79 5f 63 65 6e 74 65 72 } //01 00  awd_show_security_center
		$a_00_4 = {61 77 64 5f 75 6e 69 6e 73 74 61 6c 6c } //01 00  awd_uninstall
		$a_00_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 6c 00 65 00 72 00 74 00 73 00 2e 00 6c 00 6f 00 63 00 61 00 6c 00 2f 00 61 00 6c 00 65 00 72 00 74 00 31 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  http://alerts.local/alert1.html
		$a_00_6 = {2e 00 6c 00 6f 00 63 00 61 00 6c 00 2f 00 73 00 63 00 61 00 6e 00 5f 00 72 00 65 00 73 00 75 00 6c 00 74 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  .local/scan_results.html
		$a_00_7 = {74 00 68 00 72 00 65 00 61 00 74 00 73 00 5f 00 68 00 69 00 67 00 68 00 5f 00 63 00 6e 00 74 00 } //00 00  threats_high_cnt
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_Defmid_6{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 03 00 "
		
	strings :
		$a_01_0 = {2e 63 65 2e 6d 73 00 49 6e 74 65 72 6e 65 74 20 44 65 66 65 6e 64 65 72 20 32 30 31 31 00 } //01 00 
		$a_01_1 = {49 6e 73 74 61 6c 6c 44 65 66 65 6e 64 65 72 20 53 65 74 75 70 3a 20 49 6e 73 74 61 6c 6c 69 6e 67 } //01 00  InstallDefender Setup: Installing
		$a_03_2 = {26 43 6c 6f 73 65 00 49 6e 73 74 61 6c 6c 44 65 66 65 6e 64 65 72 90 02 05 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 90 00 } //02 00 
		$a_03_3 = {43 6f 6d 6d 6f 6e 46 69 6c 65 73 44 69 72 90 02 07 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 90 02 07 66 75 63 6b 90 00 } //03 00 
		$a_03_4 = {49 6e 74 65 72 6e 65 74 20 44 65 66 65 6e 64 65 72 20 32 30 31 31 90 02 05 47 65 74 56 65 72 73 69 6f 6e 2e 64 6c 6c 00 67 65 74 56 90 00 } //03 00 
		$a_03_5 = {49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 20 32 30 31 31 90 02 05 47 65 74 56 65 72 73 69 6f 6e 2e 64 6c 6c 00 67 65 74 56 90 00 } //03 00 
		$a_03_6 = {2e 63 65 2e 6d 73 00 53 6f 66 74 77 61 72 65 20 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 2e 2e 2e 90 02 05 47 65 74 56 65 72 73 69 6f 6e 2e 64 6c 6c 00 67 65 74 56 90 00 } //03 00 
		$a_03_7 = {2e 63 6f 2e 63 63 00 90 02 09 49 6e 73 74 61 6c 6c 90 02 10 47 65 74 56 65 72 73 69 6f 6e 2e 64 6c 6c 00 67 65 74 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_Defmid_7{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 13 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 20 44 65 66 65 6e 64 65 72 20 44 6f 77 6e 6c 6f 61 64 65 72 00 } //01 00 
		$a_01_1 = {49 6e 73 74 61 6c 6c 69 6e 67 20 53 79 73 74 65 6d 20 44 65 66 65 6e 64 65 72 00 } //01 00 
		$a_01_2 = {49 6e 73 74 61 6c 6c 69 6e 67 20 53 65 63 75 72 69 74 79 20 44 65 66 65 6e 64 65 72 00 } //01 00 
		$a_01_3 = {53 65 63 75 72 69 74 79 20 44 65 66 65 6e 64 65 72 20 44 6f 77 6e 6c 6f 61 64 65 72 00 } //01 00 
		$a_01_4 = {2f 73 77 2f 6c 2e 70 68 70 } //01 00  /sw/l.php
		$a_01_5 = {75 70 64 61 74 65 2e 64 61 74 00 } //01 00 
		$a_01_6 = {61 66 66 5f 69 64 } //01 00  aff_id
		$a_01_7 = {64 72 6f 70 70 65 72 5f 62 69 67 } //02 00  dropper_big
		$a_01_8 = {42 42 30 32 42 37 45 45 2d 35 46 43 32 2d 34 30 37 64 2d 41 36 45 43 2d 35 44 42 32 34 43 30 46 41 37 43 } //01 00  BB02B7EE-5FC2-407d-A6EC-5DB24C0FA7C
		$a_03_9 = {8b 45 fc 83 c0 01 89 90 01 02 83 90 01 03 29 73 90 01 01 8b 4d 0c 51 8b 55 08 52 e8 90 00 } //01 00 
		$a_01_10 = {88 01 0f b6 55 0c 81 f2 e9 00 00 00 } //01 00 
		$a_01_11 = {88 4a 05 0f b6 45 0c 35 e4 00 00 00 } //01 00 
		$a_01_12 = {88 50 31 0f b6 4d 0c 83 f1 5a } //01 00 
		$a_03_13 = {83 f2 09 8b 45 08 88 90 01 02 00 00 00 0f b6 4d 0c eb 90 00 } //02 00 
		$a_03_14 = {a3 a3 8b 4d 08 33 90 01 05 8b 55 08 90 00 } //01 00 
		$a_01_15 = {41 6e 74 69 6d 61 6c 77 61 72 65 20 54 6f 6f 6c 20 44 6f 77 6e 6c 6f 61 64 65 72 00 } //01 00 
		$a_01_16 = {49 6e 74 65 72 6e 65 74 20 50 72 6f 74 65 63 74 69 6f 6e } //01 00  Internet Protection
		$a_01_17 = {69 6e 73 74 61 6c 6c 20 77 6f 72 6b 65 72 00 73 74 61 72 74 00 } //02 00 
		$a_01_18 = {41 6e 74 69 76 69 72 75 73 20 43 65 6e 74 65 72 20 } //00 00  Antivirus Center 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_Defmid_8{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 15 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 4d f0 0f b6 55 0c 81 c2 0c 03 00 00 0f b6 c2 35 da 03 00 00 8b 4d 10 } //02 00 
		$a_01_1 = {35 a7 07 00 00 8b 4d 10 88 81 4a 07 00 00 0f b6 55 0c } //01 00 
		$a_01_2 = {2f 00 69 00 65 00 2e 00 67 00 69 00 66 00 00 00 } //01 00 
		$a_01_3 = {61 00 72 00 65 00 2e 00 49 00 45 00 4d 00 6f 00 } //01 00  are.IEMo
		$a_01_4 = {6e 00 6f 00 72 00 65 00 5f 00 69 00 74 00 65 00 00 00 } //01 00 
		$a_01_5 = {00 00 3a 00 2f 00 2f 00 64 00 65 00 66 00 65 00 6e 00 00 00 } //01 00 
		$a_01_6 = {20 65 6e 74 65 72 20 79 6f 75 72 20 61 63 74 00 } //01 00 
		$a_01_7 = {61 00 6c 00 65 00 72 00 74 00 38 00 2e 00 68 00 74 00 6d 00 6c 00 00 00 } //02 00 
		$a_01_8 = {56 61 6e 69 73 68 20 53 79 73 74 65 6d 20 44 65 66 65 6e 64 65 72 } //02 00  Vanish System Defender
		$a_01_9 = {0f b6 c8 81 f1 5c 04 00 00 8b 55 0c 88 8a } //01 00 
		$a_01_10 = {61 00 6c 00 65 00 72 00 74 00 36 00 2e 00 68 00 00 00 } //01 00 
		$a_01_11 = {74 00 6d 00 6c 00 00 00 53 79 73 74 65 6d 20 44 } //01 00 
		$a_01_12 = {41 00 6e 00 74 00 69 00 6d 00 61 00 6c 00 77 00 00 00 } //01 00 
		$a_01_13 = {00 69 6d 61 6c 77 61 72 65 20 54 6f 6f 6c } //01 00 
		$a_01_14 = {00 00 74 00 68 00 72 00 65 00 61 00 74 00 5f 00 73 00 00 00 } //01 00 
		$a_01_15 = {00 00 69 00 72 00 75 00 73 00 70 00 72 00 6f 00 2e 00 00 00 } //01 00 
		$a_01_16 = {00 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 2e 00 00 00 } //02 00 
		$a_00_17 = {0f b6 4d 08 81 c1 2f 07 00 00 0f b6 d1 } //01 00 
		$a_01_18 = {73 79 73 74 65 6d 20 73 63 61 6e 20 77 } //01 00  system scan w
		$a_01_19 = {00 00 2f 00 6d 00 61 00 69 00 6e 00 5f 00 73 00 63 00 00 00 } //02 00 
		$a_01_20 = {05 5e 0c 00 00 0f b6 c8 81 f1 11 0c 00 00 8b 55 0c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_Defmid_9{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 73 77 2f 6c 2e 70 68 70 3f } //01 00  /sw/l.php?
		$a_01_1 = {61 66 66 5f 69 64 } //01 00  aff_id
		$a_01_2 = {4d 61 63 68 69 6e 65 47 75 69 64 00 42 42 30 32 42 37 45 45 2d } //00 00 
	condition:
		any of ($a_*)
 
}