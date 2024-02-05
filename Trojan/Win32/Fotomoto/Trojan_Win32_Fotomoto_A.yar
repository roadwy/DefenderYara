
rule Trojan_Win32_Fotomoto_A{
	meta:
		description = "Trojan:Win32/Fotomoto.A,SIGNATURE_TYPE_PEHSTR_EXT,37 00 36 00 14 00 00 03 00 "
		
	strings :
		$a_01_0 = {26 00 6b 00 65 00 79 00 69 00 64 00 3d 00 00 00 26 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 00 00 26 00 75 00 73 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 70 00 68 00 70 00 3f 00 61 00 66 00 69 00 64 00 3d 00 } //01 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 33 00 2e 00 32 00 34 00 34 00 2e 00 31 00 34 00 31 00 2e 00 31 00 38 00 35 00 2f 00 63 00 67 00 69 00 2d 00 62 00 69 00 6e 00 } //01 00 
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 74 00 68 00 65 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 64 00 61 00 74 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00 } //03 00 
		$a_01_3 = {44 00 44 00 43 00 5f 00 53 00 74 00 6f 00 70 00 5f 00 45 00 76 00 65 00 6e 00 74 00 } //03 00 
		$a_01_4 = {25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 61 00 75 00 70 00 64 00 64 00 63 00 2e 00 65 00 78 00 65 00 } //03 00 
		$a_01_5 = {65 00 7a 00 75 00 6c 00 61 00 5f 00 64 00 65 00 6e 00 69 00 65 00 64 00 73 00 69 00 74 00 65 00 73 00 } //03 00 
		$a_01_6 = {65 00 7a 00 75 00 6c 00 61 00 5f 00 64 00 69 00 63 00 74 00 69 00 6f 00 6e 00 61 00 72 00 79 00 } //03 00 
		$a_01_7 = {65 00 7a 00 75 00 6c 00 61 00 5f 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 } //03 00 
		$a_01_8 = {65 00 7a 00 75 00 6c 00 61 00 5f 00 6d 00 61 00 78 00 64 00 75 00 70 00 } //03 00 
		$a_01_9 = {65 00 7a 00 75 00 6c 00 61 00 5f 00 6d 00 61 00 78 00 68 00 69 00 6c 00 69 00 67 00 68 00 74 00 } //03 00 
		$a_01_10 = {69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 5f 00 61 00 66 00 66 00 69 00 6c 00 69 00 61 00 74 00 65 00 5f 00 69 00 64 00 } //03 00 
		$a_01_11 = {6c 00 61 00 73 00 74 00 5f 00 65 00 7a 00 75 00 6c 00 61 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00 49 00 44 00 } //03 00 
		$a_01_12 = {6c 00 61 00 73 00 74 00 5f 00 65 00 7a 00 75 00 6c 00 61 00 73 00 79 00 6e 00 63 00 } //03 00 
		$a_01_13 = {6d 00 74 00 5f 00 6d 00 65 00 64 00 69 00 61 00 74 00 72 00 61 00 66 00 66 00 69 00 63 00 5f 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 } //03 00 
		$a_01_14 = {6d 00 74 00 5f 00 70 00 6f 00 70 00 75 00 70 00 5f 00 63 00 6f 00 75 00 6e 00 74 00 65 00 72 00 5f 00 6e 00 6f 00 74 00 69 00 66 00 79 00 } //03 00 
		$a_01_15 = {6e 00 65 00 78 00 74 00 5f 00 66 00 69 00 78 00 65 00 64 00 5f 00 63 00 74 00 78 00 5f 00 70 00 6f 00 70 00 75 00 70 00 5f 00 74 00 69 00 6d 00 65 00 } //03 00 
		$a_01_16 = {6e 00 65 00 78 00 74 00 5f 00 6d 00 74 00 5f 00 70 00 6f 00 70 00 75 00 70 00 5f 00 74 00 69 00 6d 00 65 00 } //03 00 
		$a_01_17 = {72 00 61 00 6e 00 64 00 6f 00 6d 00 5f 00 63 00 6f 00 6e 00 74 00 65 00 78 00 74 00 5f 00 62 00 6c 00 61 00 63 00 6b 00 6c 00 69 00 73 00 74 00 } //03 00 
		$a_01_18 = {72 00 65 00 6c 00 61 00 74 00 65 00 64 00 5f 00 70 00 6f 00 70 00 75 00 70 00 73 00 5f 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 } //03 00 
		$a_01_19 = {81 ec 20 02 00 00 56 68 c0 90 41 00 68 fc cb 41 00 e8 ba fc ff ff 83 c4 08 68 88 90 41 00 68 fc cb 41 00 e8 a8 fc ff ff 83 c4 08 ff 15 d8 50 41 00 68 80 90 41 00 68 fc cb 41 00 8b f0 e8 8e fc ff ff 68 68 90 41 00 56 e8 95 7a 00 00 83 c4 10 85 c0 0f 84 b8 00 00 00 68 2c 90 41 00 68 fc cb 41 00 e8 69 fc ff ff 68 98 8c 41 00 e8 4f 4f 00 00 83 c4 0c 68 f4 8f 41 00 68 fc cb 41 00 e8 4d fc ff ff 8d 44 24 0c c7 44 24 0c 00 00 00 00 50 c7 44 24 14 00 00 00 00 e8 69 79 00 00 83 c4 0c 68 b8 8f 41 00 68 fc cb 41 00 e8 21 fc ff ff 8b 35 f4 50 41 00 83 c4 08 68 98 8c 41 00 e8 2e 4d 00 00 83 c4 04 84 c0 74 29 8d 4c 24 08 51 e8 33 79 00 00 8b 54 24 0c 8b 4c 24 08 2b d1 83 c4 04 83 fa 1e 0f 8f b7 01 00 00 68 f4 01 00 00 ff d6 eb c6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fotomoto_A_2{
	meta:
		description = "Trojan:Win32/Fotomoto.A,SIGNATURE_TYPE_PEHSTR,21 00 20 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 } //0a 00 
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 46 00 69 00 6c 00 65 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //0a 00 
		$a_01_2 = {44 00 44 00 43 00 5f 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 5f 00 45 00 76 00 6e 00 74 00 } //01 00 
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 33 00 2e 00 32 00 34 00 34 00 2e 00 31 00 34 00 31 00 2e 00 31 00 38 00 35 00 2f 00 63 00 67 00 69 00 2d 00 62 00 69 00 6e 00 } //01 00 
		$a_01_4 = {25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 61 00 75 00 70 00 64 00 64 00 63 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_5 = {53 00 46 00 43 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}