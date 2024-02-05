
rule PWS_Win32_Gamania_gen_D{
	meta:
		description = "PWS:Win32/Gamania.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,67 00 66 00 16 00 00 64 00 "
		
	strings :
		$a_03_0 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 90 01 04 8b 55 f4 8b c7 e8 90 01 04 ff 45 f8 4e 75 d9 90 00 } //03 00 
		$a_01_1 = {89 44 24 18 8b 44 24 10 8b d0 83 ea 0c 83 c0 0a 2b c2 0f 8c 71 01 00 00 40 89 44 24 2c 89 54 24 20 83 7c 24 20 00 0f 8c 4f 01 00 00 8b 44 24 20 3b 44 24 18 0f 8f 41 01 00 00 8b 44 24 0c 8b d0 83 ea 17 83 c0 15 2b c2 0f 8c 2d 01 00 00 } //03 00 
		$a_03_2 = {74 03 4f 75 d2 85 db 74 0f 6a 00 6a 00 68 f5 00 00 00 53 e8 90 01 02 ff ff 90 09 43 00 74 11 6a 00 6a 00 68 f5 00 00 00 53 e8 90 00 } //03 00 
		$a_03_3 = {75 2e 6a f4 53 e8 90 01 02 ff ff 3d b4 00 00 00 74 23 6a f0 53 e8 90 01 02 ff ff a8 20 75 17 6a 00 6a 00 68 d2 00 00 00 53 e8 90 01 02 ff ff 90 00 } //03 00 
		$a_01_4 = {8a 18 8b cb 80 e1 07 81 e1 ff 00 00 00 51 b9 07 00 00 00 5f 2b cf bf 01 00 00 00 d3 e7 33 c9 8a cb c1 e9 03 0f b6 0c 0e 23 f9 74 1a 8b ca 83 e1 07 51 b9 07 00 00 00 5b 2b cb b3 01 d2 e3 8b ca c1 e9 03 08 1c 0c 42 40 83 fa 40 75 b3 } //03 00 
		$a_03_5 = {7e 2c be 01 00 00 00 8d 45 f0 8b 55 fc 0f b6 54 32 ff 4a d1 fa 79 03 83 d2 00 e8 90 01 02 ff ff 8b 55 f0 8d 45 f8 e8 90 01 02 ff ff 46 4b 75 d9 90 00 } //03 00 
		$a_03_6 = {7e 23 be 01 00 00 00 b8 18 00 00 00 e8 90 01 02 ff ff 83 c0 61 50 8b c7 e8 90 01 02 ff ff 5a 88 54 30 ff 46 4b 75 e2 90 00 } //38 ff 
		$a_03_7 = {0f 84 2d 01 00 00 6a 00 53 e8 90 01 02 ff ff 8b f0 81 fe 00 00 00 01 0f 83 11 01 00 00 3b 35 90 01 04 7c 34 90 00 } //38 ff 
		$a_03_8 = {8b 55 fc e8 90 01 02 ff ff 8b 85 90 01 02 ff ff e8 90 01 02 ff ff 56 57 e8 90 01 02 ff ff 85 c0 75 84 57 e8 90 01 02 ff ff c7 06 16 00 00 00 90 00 } //03 00 
		$a_00_9 = {d2 e1 f6 cd ef ee ae e5 f8 e5 00 } //03 00 
		$a_00_10 = {d2 e1 f6 cd ef ee c3 ec e1 f3 f3 00 } //03 00 
		$a_00_11 = {d3 ef e6 f4 f7 e1 f2 e5 dc c8 e1 e3 eb e5 f2 dc 00 } //01 00 
		$a_00_12 = {c9 d0 c1 d2 cd cf d2 ae c5 d8 c5 00 } //02 00 
		$a_00_13 = {4a 75 6d 70 48 6f 6f 6b 4f 6e } //01 00 
		$a_00_14 = {4a 75 6d 70 48 6f 6f 6b 4f 66 66 } //01 00 
		$a_00_15 = {64 65 6c 20 25 30 00 } //01 00 
		$a_01_16 = {6a 53 74 61 00 } //01 00 
		$a_01_17 = {6a 53 74 62 00 } //01 00 
		$a_00_18 = {ae c5 d8 c5 00 } //01 00 
		$a_00_19 = {ae d4 d8 d4 00 } //01 00 
		$a_00_20 = {cd e1 f0 c6 e9 ec e5 00 } //01 00 
		$a_00_21 = {c3 cc d3 c9 c4 dc 00 } //01 00 
	condition:
		any of ($a_*)
 
}