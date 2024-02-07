
rule Ransom_Win32_Betisrypt_D{
	meta:
		description = "Ransom:Win32/Betisrypt.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0c 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } ///c vssadmin.exe Delete Shadows /All /Quiet  01 00 
		$a_80_1 = {2f 63 20 62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } ///c bcdedit.exe /set {default} recoveryenabled No  01 00 
		$a_80_2 = {2f 63 20 62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } ///c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures  01 00 
		$a_80_3 = {6e 6f 63 74 75 72 6e 61 6c 6e 6f 63 74 75 72 6e 61 6c 6e 6f 63 74 75 72 6e 61 6c 6e 6f 63 74 75 72 6e 61 6c } //nocturnalnocturnalnocturnalnocturnal  01 00 
		$a_00_4 = {00 25 73 2e 5b 25 73 5d 2d 69 64 2d 25 58 2e } //01 00 
		$a_00_5 = {50 47 6c 74 5a 79 42 7a 63 6d 4d 39 4a 32 52 68 64 47 45 36 61 57 31 68 5a 32 55 76 63 47 35 6e 4f 32 4a 68 63 32 55 32 4e 43 78 70 56 6b 4a 50 55 67 30 4b } //02 00  PGltZyBzcmM9J2RhdGE6aW1hZ2UvcG5nO2Jhc2U2NCxpVkJPUg0K
		$a_01_6 = {83 fe 02 7d 05 83 f8 02 74 17 83 f8 03 74 0a 83 f8 02 74 05 83 f8 04 75 08 8d 46 41 } //01 00 
		$a_03_7 = {68 10 66 00 00 ff 75 90 01 01 ff 15 90 01 04 8b 35 90 01 04 8d 45 90 01 01 6a 00 50 6a 04 ff 75 90 01 01 ff d6 90 00 } //02 00 
		$a_03_8 = {68 00 00 a0 00 68 90 01 04 53 ff 15 90 01 04 8b 35 90 01 04 8d 45 90 01 01 68 00 00 a0 00 50 6a 00 6a 00 6a 01 6a 00 ff 75 90 01 01 ff d6 90 00 } //01 00 
		$a_03_9 = {ff d7 56 ff d3 6a 00 6a 00 6a 03 6a 00 6a 01 68 00 01 00 40 ff 75 90 01 01 ff 15 90 00 } //01 00 
		$a_03_10 = {ff 75 20 8d 4d 10 0f 43 4d 10 51 56 ff d7 56 ff d3 8b 45 90 01 01 85 c0 74 0e 90 00 } //01 00 
		$a_03_11 = {6a 01 56 53 ff 15 90 01 04 8b 45 24 83 f8 10 72 42 8b 4d 10 40 3d 00 10 00 00 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}