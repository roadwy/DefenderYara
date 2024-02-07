
rule Backdoor_Win32_Venixol_B{
	meta:
		description = "Backdoor:Win32/Venixol.B,SIGNATURE_TYPE_PEHSTR_EXT,0e 01 ffffffe6 00 0d 00 00 ffffff82 00 "
		
	strings :
		$a_01_0 = {8a 04 18 8a 16 02 c2 00 45 fe 0f b6 45 fe 03 c1 8a 18 fe 45 ff 88 1e 88 10 66 0f b6 45 ff } //3c 00 
		$a_01_1 = {bf 46 39 08 26 3c 5a 18 08 fb 35 74 b4 4d 00 } //3c 00 
		$a_01_2 = {b3 49 64 08 36 2a 4f 07 43 fd 39 00 } //1e 00 
		$a_01_3 = {1b 86 e5 41 c7 74 aa df ae d1 8d c0 58 25 fc 7b 26 04 05 7f 7e 14 97 0c 5f b6 07 92 6d 9e 49 60 } //1e 00 
		$a_01_4 = {92 4b e9 b6 8b 78 8c a5 0a a4 02 a3 87 cb 78 a9 2e 42 6c 08 6e b1 1f 6d 3a c0 14 12 0c 35 6a de } //1e 00 
		$a_01_5 = {35 05 13 4e 6e 10 95 46 1b e0 37 a5 6c 83 4b 35 c9 82 8a 74 } //1e 00 
		$a_01_6 = {97 9a 92 60 5e 21 83 69 f2 4d 04 c8 8c 92 77 34 a5 f4 11 26 88 5f c4 35 38 e9 21 f8 a3 76 99 c7 } //1e 00 
		$a_01_7 = {81 5a 65 1f 35 3d 01 5e 2c ff 2d 39 ae 5d 99 f6 50 c0 bb 13 80 39 d4 9f f2 e3 b7 e0 03 } //1e 00 
		$a_01_8 = {d3 0e ad 2f c7 1e 65 95 9c c4 28 4b 5f d2 33 a1 7d 05 e6 88 99 31 60 ec f8 11 30 cb 0a 98 7a 0a } //1e 00 
		$a_01_9 = {b5 5a 63 47 20 27 4b } //1e 00 
		$a_01_10 = {f2 0b 27 5a 70 09 54 0c 0f e6 28 3e a3 56 } //14 00 
		$a_01_11 = {59 57 52 74 61 57 34 36 } //14 00  YWRtaW46
		$a_01_12 = {56 45 4e 49 58 33 4e 31 63 47 56 79 58 32 4e 7a 62 54 70 36 64 47 55 6b 4e 7a 51 78 4e 54 63 77 4f 47 46 32 62 47 6c 7a } //00 00  VENIX3N1cGVyX2NzbTp6dGUkNzQxNTcwOGF2bGlz
		$a_00_13 = {5d 04 00 00 29 fb 02 80 5c 22 00 00 2a fb 02 80 00 00 01 00 08 00 0c 00 ac 21 54 61 72 63 6c 6f 69 6e 2e 43 00 00 01 40 05 82 70 00 04 00 78 71 01 00 03 00 03 00 03 00 00 01 00 60 01 34 30 37 37 35 30 37 32 38 30 37 39 37 30 38 38 39 30 34 } //32 31 
	condition:
		any of ($a_*)
 
}