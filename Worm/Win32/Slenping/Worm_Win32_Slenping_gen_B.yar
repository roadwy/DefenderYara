
rule Worm_Win32_Slenping_gen_B{
	meta:
		description = "Worm:Win32/Slenping.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0d 00 0f 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 53 6b 4d 61 69 6e 46 6f 72 6d 2e 55 6e 69 63 6f 64 65 43 6c 61 73 73 } //01 00  tSkMainForm.UnicodeClass
		$a_00_1 = {50 75 54 54 59 } //01 00  PuTTY
		$a_00_2 = {54 46 72 6d 4d 61 69 6e } //01 00  TFrmMain
		$a_00_3 = {59 61 68 6f 6f 42 75 64 64 79 4d 61 69 6e } //01 00  YahooBuddyMain
		$a_00_4 = {4d 53 42 4c 57 69 6e 64 6f 77 43 6c 61 73 73 } //01 00  MSBLWindowClass
		$a_00_5 = {5f 4f 73 63 61 72 5f 53 74 61 74 75 73 4e 6f 74 69 66 79 } //01 00  _Oscar_StatusNotify
		$a_00_6 = {5f 5f 6f 78 46 72 61 6d 65 2e 63 6c 61 73 73 5f 5f } //01 00  __oxFrame.class__
		$a_00_7 = {25 73 5c 72 65 6d 6f 76 65 4d 65 25 69 25 69 25 69 25 69 2e 62 61 74 } //01 00  %s\removeMe%i%i%i%i.bat
		$a_00_8 = {70 69 6e 67 20 30 2e 30 2e 30 2e 30 3e 6e 75 6c } //01 00  ping 0.0.0.0>nul
		$a_00_9 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 25 73 22 20 45 4e 41 42 4c 45 } //05 00  netsh firewall set allowedprogram "%s" ENABLE
		$a_01_10 = {6d 47 fe 74 e8 bf c2 45 90 35 d1 5e 33 0a 24 6d } //0a 00 
		$a_01_11 = {55 6a 01 55 6a 11 ff d6 55 55 55 6a 56 ff d3 50 ff d6 55 6a 03 6a 2d 6a 11 ff d6 } //0a 00 
		$a_03_12 = {56 6a 01 56 6a 11 ff d3 56 56 56 6a 56 90 01 06 50 ff d3 56 6a 03 6a 2d 6a 11 ff d3 90 00 } //0f 00 
		$a_03_13 = {3d 46 27 00 00 74 90 01 01 03 f0 83 fe 0c 7d 90 01 01 6a 00 b9 0c 00 00 00 2b ce 51 8d 54 34 90 01 01 52 55 ff d7 90 00 } //0f 00 
		$a_03_14 = {3d 46 27 00 00 74 90 01 01 03 f8 3b 7d 90 01 01 7d 90 01 01 8b 45 0c 6a 00 2b c7 50 8d 04 1f 50 ff 75 90 01 01 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}