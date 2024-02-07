
rule Worm_Win32_Autorun_gen_BA{
	meta:
		description = "Worm:Win32/Autorun.gen!BA,SIGNATURE_TYPE_PEHSTR_EXT,19 00 16 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6d 69 63 72 6f 73 6f 66 74 20 76 69 73 75 61 6c 20 63 2b 2b 20 72 75 6e 74 69 6d 65 20 6c 69 62 72 61 72 79 } //0a 00  microsoft visual c++ runtime library
		$a_01_1 = {74 12 8a 50 01 3a 51 01 75 0e 83 c0 02 83 c1 02 84 d2 75 e4 33 c0 eb 05 1b c0 83 d8 ff 85 c0 0f 85 b8 00 00 00 53 55 57 8d 54 24 14 52 56 ff 15 } //01 00 
		$a_00_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 70 69 63 73 2e 65 78 65 } //01 00  shell\open\Command=pics.exe
		$a_00_3 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 64 6f 77 6e 6c 6f 61 64 73 2e 65 78 65 } //01 00  shell\explore\Command=downloads.exe
		$a_00_4 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 66 75 6e 2e 65 78 65 } //01 00  shell\explore\Command=fun.exe
		$a_00_5 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 64 6f 63 75 6d 65 6e 74 73 2e 65 78 65 } //01 00  shell\explore\Command=documents.exe
		$a_00_6 = {25 63 3a 5c 6b 69 6c 6c 76 62 73 2e 76 62 73 } //01 00  %c:\killvbs.vbs
		$a_00_7 = {67 6f 64 73 20 6d 75 73 74 20 62 65 20 63 72 } //00 00  gods must be cr
	condition:
		any of ($a_*)
 
}