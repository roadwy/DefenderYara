
rule Worm_Win32_Nanspy_G{
	meta:
		description = "Worm:Win32/Nanspy.G,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 8b ec 81 c4 c8 fe ff ff 53 56 57 33 d2 89 95 c8 fe ff ff 89 45 fc 33 c0 55 68 46 44 40 00 64 ff 30 64 89 20 8d 45 98 33 c9 ba 44 00 00 00 e8 5c e9 ff ff c7 45 98 44 00 00 00 8d 45 dc 50 8d 45 98 50 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8d 95 c8 fe ff ff 33 c0 e8 80 e4 ff ff 8b 85 c8 fe ff ff e8 5d f4 ff ff 50 6a 00 e8 5d fe ff ff 33 d2 55 68 26 44 40 00 64 ff 32 64 89 } //01 00 
		$a_00_1 = {22 33 d2 55 68 ec 43 40 00 64 ff 32 64 89 22 c7 85 cc fe ff ff 02 00 01 00 e8 a2 e4 ff ff b8 64 00 00 00 e8 0c e9 ff ff 8b d8 b8 16 00 00 00 e8 00 e9 ff ff 3b d8 75 13 6a 00 68 54 44 40 00 68 54 44 40 00 6a 00 e8 4d fe ff ff 8d 85 cc fe ff ff 50 8b 45 e0 50 e8 fd fd ff ff 8d 45 f0 50 6a 04 8d 45 f8 50 8b 85 70 ff ff ff 83 c0 08 50 8b 45 dc 50 e8 e8 fd ff ff 8b 45 f8 50 } //01 00 
		$a_00_2 = {8b 45 dc 50 e8 53 fe ff ff 8b 45 fc 33 d2 52 50 8b 45 fc 8b 40 3c 99 03 04 24 13 54 24 04 83 c4 08 8b f8 6a 40 68 00 30 00 00 8b 47 50 50 8b 47 34 50 8b 45 dc 50 e8 c9 fd ff ff 89 45 f4 8d 45 f0 50 8b 47 54 50 8b 45 fc 50 8b 45 f4 50 8b 45 dc 50 e8 bd fd ff ff 8b df 81 c3 f8 00 00 00 0f b7 77 06 4e 85 f6 72 50 46 8b 43 10 85 c0 76 42 8d 55 f0 52 50 8b 43 14 03 45 fc 50 } //01 00 
		$a_00_3 = {8b 43 0c 03 45 f4 50 8b 45 dc 50 e8 88 fd ff ff 8d 45 ec 50 8b 43 24 c1 e8 1d 8b 04 85 c4 50 40 00 50 8b 43 10 50 8b 43 0c 03 45 f4 50 8b 45 dc 50 e8 5a fd ff ff 83 c3 28 4e 75 b1 8d 45 f0 50 6a 04 8d 45 f4 50 8b 85 70 ff ff ff 83 c0 08 50 8b 45 dc 50 e8 3f fd ff ff 8b 47 28 03 45 f4 89 85 7c ff ff ff 8d 85 cc fe ff ff 50 8b 45 e0 50 e8 03 fd ff ff 8b 45 e0 50 e8 f2 fc } //01 00 
		$a_00_4 = {ff ff 33 c0 5a 59 59 64 89 10 eb 1a e9 27 eb ff ff 6a 00 8b 45 dc 50 e8 e8 fc ff ff e8 7b ec ff ff e8 ca ec ff ff 33 c0 5a 59 59 64 89 10 68 2d 44 40 00 8b 45 dc 50 e8 98 fc ff ff 8b 45 e0 50 e8 8f fc ff ff c3 } //01 00 
		$a_01_5 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00 
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00 
		$a_01_7 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00 
		$a_01_8 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //01 00 
		$a_01_9 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}