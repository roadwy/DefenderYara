
rule Trojan_Win32_Powessere_A_{
	meta:
		description = "Trojan:Win32/Powessere.A!!Powessere.D,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 22 00 5c 00 2e 00 2e 00 5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 52 00 75 00 6e 00 48 00 54 00 4d 00 4c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 22 00 3b 00 65 00 76 00 61 00 6c 00 } //01 00 
		$a_00_1 = {61 69 64 3d 25 73 26 62 75 69 6c 64 64 61 74 65 3d 25 73 26 69 64 3d 25 73 26 6f 73 3d 25 73 5f } //01 00 
		$a_00_2 = {69 65 78 20 28 5b 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 41 53 43 49 49 2e 47 65 74 53 74 72 69 6e 67 28 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 7b 6c 6f 61 64 65 72 7d 27 29 29 29 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Powessere_A__2{
	meta:
		description = "Trojan:Win32/Powessere.A!!Powessere.D,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 6b 58 6a 65 66 89 45 90 01 01 58 6a 72 66 89 45 90 01 01 58 6a 6e 66 89 45 90 01 01 58 6a 65 66 89 45 90 01 01 58 6a 6c 90 00 } //01 00 
		$a_01_1 = {32 45 ff b1 08 2a cb 8a d0 d2 ea 8b cb d2 e0 0a d0 88 54 3e 01 ff 45 f8 fe 45 ff 8b 45 f8 fe 45 fe 3b 45 0c 72 } //01 00 
		$a_00_2 = {3d 63 6d 64 5f 25 75 26 76 65 72 73 69 6f 6e 3d } //01 00 
		$a_00_3 = {3d 64 65 62 75 67 5f 75 6d 33 5f 25 73 26 76 65 72 73 69 6f 6e 3d } //01 00 
		$a_00_4 = {72 65 69 6e 73 74 6f 6b } //01 00 
		$a_00_5 = {25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 73 } //01 00 
		$a_00_6 = {65 67 70 6e 61 6d 65 5f 25 78 5f 25 78 } //01 00 
		$a_00_7 = {3a 2f 2f 25 73 2f 71 00 73 6f 66 74 77 61 72 65 5c 63 6c 61 73 73 65 73 5c 63 6c 73 69 64 5c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Powessere_A__3{
	meta:
		description = "Trojan:Win32/Powessere.A!!Powessere.D,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 0f 00 00 02 00 "
		
	strings :
		$a_01_0 = {5b f7 f3 83 fa 0a 72 03 83 c2 27 80 c2 30 88 94 3d f0 fe ff ff 47 3b fe 72 ce } //03 00 
		$a_03_1 = {69 d2 04 01 00 00 81 c2 90 01 04 52 57 ff 15 90 01 04 83 c4 0c e8 90 01 04 85 c0 75 16 68 60 ea 00 00 ff d5 43 83 fb 03 72 bb 68 c0 27 09 00 ff d5 eb b0 90 00 } //02 00 
		$a_00_2 = {61 00 69 00 64 00 3a 00 20 00 25 00 53 00 0d 00 0a 00 62 00 75 00 69 00 6c 00 64 00 64 00 61 00 74 00 65 00 3a 00 20 00 25 00 53 00 0d 00 0a 00 70 00 69 00 64 00 3a 00 20 00 25 00 78 00 } //02 00 
		$a_00_3 = {2d 00 6b 00 68 00 62 00 37 00 34 00 37 00 62 00 6a 00 67 00 33 00 32 00 34 00 79 00 75 00 } //01 00 
		$a_00_4 = {3c 63 6c 69 63 6b 75 72 6c 3e } //01 00 
		$a_00_5 = {7b 73 65 72 76 65 72 7d 2f 71 75 65 72 79 3f 76 65 72 73 69 6f 6e 3d } //01 00 
		$a_00_6 = {62 75 69 6c 64 64 61 74 65 3d 7b 62 75 69 6c 64 64 61 74 65 7d } //01 00 
		$a_00_7 = {77 74 3d 7b 74 68 72 65 61 64 73 7d } //01 00 
		$a_00_8 = {6c 72 3d 7b 6c 61 73 74 72 65 73 75 6c 74 7d } //01 00 
		$a_00_9 = {6c 73 3d 7b 6c 61 73 74 73 74 61 67 65 7d } //01 00 
		$a_00_10 = {25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 2a 5b 5e 3b 5d 3b 25 2a 5b 5e 3b 5d 3b 25 75 } //01 00 
		$a_00_11 = {25 2a 5b 5e 3b 5d 3b 25 2a 5b 5e 3b 5d 3b 25 2a 5b 5e 3b 5d 3b 25 2a 5b 5e 3b 5d 3b 25 75 } //02 00 
		$a_00_12 = {64 65 67 65 6e 65 72 61 74 69 76 65 2b 6a 6f 69 6e 74 2b 64 69 73 65 61 73 65 } //02 00 
		$a_00_13 = {61 6e 74 69 2b 61 67 69 6e 67 2b 73 6b 69 6e 2b 63 61 72 65 } //02 00 
		$a_00_14 = {6f 6e 6c 69 6e 65 2b 61 75 74 6f 2b 69 6e 73 75 72 61 6e 63 65 2b 71 75 6f 74 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Powessere_A__4{
	meta:
		description = "Trojan:Win32/Powessere.A!!Powessere.D,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 0d 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 6b 58 6a 65 66 89 45 90 01 01 58 6a 72 66 89 45 90 01 01 58 6a 6e 66 89 45 90 01 01 58 6a 65 66 89 45 90 01 01 58 6a 6c 66 89 45 90 01 01 58 6a 33 66 89 45 90 01 01 58 6a 32 90 00 } //01 00 
		$a_03_1 = {4c 6f 61 64 c7 45 90 01 01 4c 69 62 72 c7 45 90 01 01 61 72 79 41 c6 45 90 01 01 00 c7 45 90 01 01 47 65 74 50 c7 45 90 01 01 72 6f 63 41 c7 45 90 01 01 64 64 72 65 90 00 } //01 00 
		$a_03_2 = {ff 55 f0 8b 75 08 8b 9e 90 01 02 00 00 81 c6 90 01 02 00 00 6a 40 68 00 30 00 00 03 de 90 00 } //02 00 
		$a_01_3 = {26 61 69 64 3d 25 73 26 62 75 69 6c 64 64 61 74 65 3d 25 73 26 69 64 3d 25 73 26 6f 73 3d 25 73 5f 25 73 } //01 00 
		$a_01_4 = {25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 73 } //02 00 
		$a_02_5 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 22 00 5c 00 2e 00 2e 00 5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 90 02 04 2c 00 52 00 75 00 6e 00 48 00 54 00 4d 00 4c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 90 00 } //02 00 
		$a_02_6 = {6a 61 76 61 73 63 72 69 70 74 3a 22 5c 2e 2e 5c 6d 73 68 74 6d 6c 90 02 04 2c 52 75 6e 48 54 4d 4c 41 70 70 6c 69 63 61 74 69 6f 6e 90 00 } //01 00 
		$a_80_7 = {7b 37 33 45 37 30 39 45 41 2d 35 44 39 33 2d 34 42 32 45 2d 42 42 42 30 2d 39 39 42 37 39 33 38 44 41 39 45 34 7d } //{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}  01 00 
		$a_80_8 = {7b 41 42 38 39 30 32 42 34 2d 30 39 43 41 2d 34 62 62 36 2d 42 37 38 44 2d 41 38 46 35 39 30 37 39 41 38 44 35 7d } //{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}  01 00 
		$a_03_9 = {eb 15 8d 85 90 01 02 ff ff 50 ff 14 f5 90 01 04 85 c0 74 03 33 db 43 8d 77 01 85 ff 75 90 00 } //04 00 
		$a_03_10 = {eb 02 33 ff ff 74 24 10 ff 15 90 01 04 3b fe 75 10 68 88 13 00 00 ff 15 90 01 04 e9 90 01 04 8b 3d 90 01 04 c7 44 24 14 90 01 04 8b 44 24 14 8b 00 b9 90 01 04 83 f8 05 74 05 b9 90 01 04 56 8d 54 24 14 52 56 68 3f 01 0f 00 90 00 } //f6 ff 
		$a_01_11 = {5c 41 64 6c 69 63 65 5c 52 6f 67 75 65 4b 69 6c 6c 65 72 } //f6 ff 
		$a_01_12 = {53 69 67 6e 61 74 75 72 65 42 6c 61 63 6b 6c 69 73 74 52 75 6c 65 50 6f 77 65 6c 69 6b 73 } //00 00 
	condition:
		any of ($a_*)
 
}