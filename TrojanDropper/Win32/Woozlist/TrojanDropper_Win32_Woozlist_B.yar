
rule TrojanDropper_Win32_Woozlist_B{
	meta:
		description = "TrojanDropper:Win32/Woozlist.B,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 72 6e 6c 6e 2e 66 6e 72 } //01 00 
		$a_03_1 = {69 65 78 74 33 90 02 03 7b 42 36 46 37 35 34 32 46 2d 42 38 46 45 2d 34 36 61 38 2d 39 36 30 35 2d 39 38 38 35 36 41 36 38 37 30 39 37 7d 90 00 } //01 00 
		$a_01_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 62 00 61 00 62 00 79 00 } //01 00 
		$a_03_3 = {2e 73 79 73 90 02 05 50 61 73 74 90 00 } //05 00 
		$a_03_4 = {5c 65 74 63 5c 68 6f 73 74 73 90 02 10 68 74 74 70 3a 2f 2f 90 00 } //05 00 
		$a_01_5 = {2f 67 6f 6e 67 67 61 6f 2e 74 78 74 2f } //05 00 
		$a_01_6 = {2e 74 6d 70 } //00 00 
		$a_00_7 = {78 b5 00 00 08 00 08 00 08 00 00 01 } //00 0b 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Woozlist_B_2{
	meta:
		description = "TrojanDropper:Win32/Woozlist.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 79 77 74 2e 63 6f 6d 2e 63 6e } //01 00 
		$a_01_1 = {3d 3f 67 62 32 33 31 32 3f 42 3f } //01 00 
		$a_01_2 = {64 30 39 66 32 33 34 30 38 31 38 35 31 31 64 33 39 36 66 36 61 61 66 38 34 34 63 37 65 33 32 35 } //01 00 
		$a_01_3 = {37 30 37 63 61 33 37 33 32 32 34 37 34 66 36 63 61 38 34 31 66 30 65 32 32 34 66 34 62 36 32 30 } //01 00 
		$a_03_4 = {5c 65 74 63 5c 68 6f 73 74 73 90 02 10 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_01_5 = {46 72 6f 6d 3a 20 25 73 } //01 00 
		$a_01_6 = {53 75 62 6a 65 63 74 3a 20 25 73 } //01 00 
		$a_01_7 = {43 3a 5c 75 73 65 72 2e 65 78 65 } //00 00 
		$a_00_8 = {78 12 01 00 09 } //00 09 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Woozlist_B_3{
	meta:
		description = "TrojanDropper:Win32/Woozlist.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 79 77 74 2e 63 6f 6d 2e 63 6e } //01 00 
		$a_01_1 = {3d 3f 67 62 32 33 31 32 3f 42 3f } //01 00 
		$a_01_2 = {64 30 39 66 32 33 34 30 38 31 38 35 31 31 64 33 39 36 66 36 61 61 66 38 34 34 63 37 65 33 32 35 } //01 00 
		$a_01_3 = {37 30 37 63 61 33 37 33 32 32 34 37 34 66 36 63 61 38 34 31 66 30 65 32 32 34 66 34 62 36 32 30 } //01 00 
		$a_01_4 = {46 72 6f 6d 3a 20 25 73 } //01 00 
		$a_01_5 = {53 75 62 6a 65 63 74 3a 20 25 73 } //01 00 
		$a_03_6 = {53 53 4f 41 78 43 74 72 6c 46 6f 72 50 54 4c 6f 67 69 6e 2e 53 53 4f 46 6f 72 50 54 4c 6f 67 69 6e 32 90 02 10 68 74 74 70 3a 2f 2f 78 75 69 2e 70 74 6c 6f 67 69 6e 32 2e 71 71 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 71 6c 6f 67 69 6e 90 02 20 53 69 6c 65 6e 74 90 00 } //01 00 
		$a_01_7 = {43 3a 5c 66 73 64 6c 6b 6a 73 6b 6c 2e 65 78 65 } //01 00 
		$a_01_8 = {8b d1 57 8b f8 c1 e9 02 f3 a5 8b ca 55 83 e1 03 50 f3 a4 } //00 00 
	condition:
		any of ($a_*)
 
}