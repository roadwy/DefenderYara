
rule TrojanDropper_Win32_Vtimrun_B{
	meta:
		description = "TrojanDropper:Win32/Vtimrun.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {7e 03 6a 10 58 57 8d 4d 90 01 01 51 50 8d 45 90 01 01 50 ff 75 fc ff 15 90 01 02 40 00 83 6d 90 01 01 10 83 45 90 01 01 10 43 3b 1e 7c c7 90 00 } //02 00 
		$a_01_1 = {3b c7 74 0c ff 75 fc ff 75 f4 ff d0 85 c0 75 06 53 e9 81 00 00 00 39 7d f0 74 15 } //02 00 
		$a_01_2 = {83 7d f4 02 75 14 83 7d e8 05 75 0e 33 c0 40 83 7d ec 00 74 07 39 45 ec 74 02 32 c0 } //01 00 
		$a_01_3 = {25 73 5c 25 64 5f 72 65 73 2e 74 6d 70 } //01 00  %s\%d_res.tmp
		$a_03_4 = {5f 4d 69 73 73 69 6f 6e 42 72 69 65 66 69 6e 67 40 90 02 07 5f 49 6e 73 74 61 6c 6c 40 90 00 } //01 00 
		$a_03_5 = {41 64 64 41 63 63 65 73 73 41 6c 6c 6f 77 65 64 41 63 65 45 78 90 02 07 5c 44 72 69 76 65 72 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}