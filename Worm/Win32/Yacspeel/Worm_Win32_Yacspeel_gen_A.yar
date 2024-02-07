
rule Worm_Win32_Yacspeel_gen_A{
	meta:
		description = "Worm:Win32/Yacspeel.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 0e 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {74 b1 8b 44 24 14 50 ff 15 14 00 01 10 b9 90 01 01 5b 01 10 e8 90 01 02 00 00 68 00 5c 26 05 ff 15 90 01 02 01 10 8b 0d 90 01 01 5b 01 10 6a 01 81 c1 20 07 00 00 6a 04 51 b9 90 00 } //0a 00 
		$a_02_1 = {74 24 8d 54 24 10 52 e8 ef 31 00 00 83 c4 04 e8 90 01 01 cd ff ff 8b 46 0c 8b 4c 24 10 89 48 10 8b 4e 0c e8 73 01 00 00 68 00 5c 26 05 ff d7 8b 15 90 01 01 5b 01 10 8b 82 44 08 00 00 85 c0 75 2f 8b ce e8 25 09 00 00 85 c0 74 24 90 00 } //0a 00 
		$a_00_2 = {6d 69 63 72 6f 73 6f 66 74 20 76 69 73 75 61 6c 20 63 2b 2b 20 72 75 6e 74 69 6d 65 20 6c 69 62 72 61 72 79 } //01 00  microsoft visual c++ runtime library
		$a_00_3 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 2e 5c 64 65 73 6b 74 6f 70 2e 64 6c 6c 2c 49 6e 73 74 61 6c 6c 4d } //01 00  shell\open\Command=rundll32.exe .\desktop.dll,InstallM
		$a_00_4 = {74 69 6d 6f 75 74 } //01 00  timout
		$a_00_5 = {53 6c 65 65 70 69 6e 67 44 61 79 73 43 6e 74 } //01 00  SleepingDaysCnt
		$a_00_6 = {7b 31 41 45 46 41 35 35 46 2d 36 30 41 36 2d 34 38 31 37 2d 42 32 44 35 2d 31 32 45 32 45 34 38 36 31 37 46 34 7d } //00 00  {1AEFA55F-60A6-4817-B2D5-12E2E48617F4}
	condition:
		any of ($a_*)
 
}