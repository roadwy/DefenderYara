
rule PWS_Win32_Zbot_gen_AK{
	meta:
		description = "PWS:Win32/Zbot.gen!AK,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc8 00 07 00 00 64 00 "
		
	strings :
		$a_01_0 = {77 12 8b 45 10 29 01 8b 01 03 45 08 89 01 8b 7d e4 8b 45 e0 46 eb c3 03 52 04 eb a4 83 4d fc ff b0 01 eb 0d } //32 00 
		$a_01_1 = {66 33 c8 66 33 cf b8 ff 00 00 00 66 23 c8 47 66 89 0c 53 66 3b 3c f5 } //32 00 
		$a_01_2 = {74 4c 66 83 39 2d 75 46 0f b7 41 02 83 e8 66 74 3a 83 e8 08 74 30 83 e8 06 74 26 48 } //32 00 
		$a_01_3 = {74 24 66 83 38 2d 75 1e 0f b7 40 02 83 e8 6e 74 12 83 e8 06 74 08 48 } //01 00 
		$a_01_4 = {83 c4 0c 2b ce 8a 04 31 30 06 46 4f 75 f7 } //01 00 
		$a_01_5 = {8b 4f 3c 03 cf 83 b9 a4 00 00 00 00 0f 84 99 00 00 00 8b 91 a0 00 00 00 85 d2 0f 84 8b 00 00 00 } //01 00 
		$a_03_6 = {eb 07 83 25 90 01 04 00 83 3d 90 01 04 00 0f 84 90 01 02 00 00 a1 90 01 04 a9 e0 0f 00 00 0f 84 90 01 02 00 00 a9 00 08 00 00 74 90 01 01 90 03 01 01 b9 68 b8 01 00 00 90 00 } //00 00 
		$a_00_7 = {80 10 00 00 94 ea 57 14 16 0e f0 40 d1 f2 77 d3 00 10 00 80 5d 04 00 00 fb c4 02 80 5c 21 00 00 fc c4 02 80 00 00 01 00 28 00 0b 00 dc 21 42 61 6e 6b 65 } //72 2e 
	condition:
		any of ($a_*)
 
}