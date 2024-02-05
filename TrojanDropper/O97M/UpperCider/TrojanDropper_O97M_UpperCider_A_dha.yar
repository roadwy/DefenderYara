
rule TrojanDropper_O97M_UpperCider_A_dha{
	meta:
		description = "TrojanDropper:O97M/UpperCider.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 0c 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 6f 6d 6d 61 6e 64 4d 6f 76 65 54 6f 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 25 74 65 6d 70 25 5c 5c 90 02 10 2a 20 22 20 26 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 22 2a 22 90 00 } //01 00 
		$a_03_1 = {64 73 74 43 6f 70 79 54 6f 90 02 04 20 3d 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 22 90 02 14 22 90 00 } //01 00 
		$a_03_2 = {4f 62 6a 52 75 6e 20 43 6f 6d 6d 61 6e 64 4d 6f 76 65 54 6f 2c 20 64 73 74 43 6f 70 79 54 6f 90 02 04 2c 20 64 73 74 43 6f 70 79 54 6f 90 02 04 2c 20 64 73 74 43 6f 70 79 54 6f 90 02 04 2c 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 90 00 } //01 00 
		$a_03_3 = {53 75 62 20 4f 62 6a 52 75 6e 28 43 6f 6d 6d 61 6e 64 4d 6f 76 65 54 6f 20 41 73 20 53 74 72 69 6e 67 2c 20 43 6f 70 79 54 6f 90 02 04 20 41 73 20 53 74 72 69 6e 67 2c 20 43 6f 70 79 54 6f 90 02 04 20 41 73 20 53 74 72 69 6e 67 2c 20 43 6f 70 79 54 6f 90 02 04 20 41 73 20 53 74 72 69 6e 67 2c 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 41 73 20 53 74 72 69 6e 67 29 90 00 } //01 00 
		$a_01_4 = {63 65 72 6d 6f 76 65 43 6f 6d 61 6e 64 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 25 77 69 6e 64 69 72 25 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 63 65 72 74 75 74 69 6c 2e 65 78 65 20 } //01 00 
		$a_03_5 = {63 65 72 74 75 74 69 6c 43 6f 6d 61 6e 64 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 90 02 20 20 2d 64 65 63 6f 64 65 20 22 90 00 } //01 00 
		$a_01_6 = {6f 62 6a 77 73 2e 52 75 6e 20 43 6f 6d 6d 61 6e 64 4d 6f 76 65 54 6f 2c 20 30 2c 20 54 72 75 65 } //01 00 
		$a_01_7 = {6f 62 6a 77 73 2e 52 75 6e 20 63 65 72 6d 6f 76 65 43 6f 6d 61 6e 64 2c 20 30 2c 20 54 72 75 65 } //01 00 
		$a_03_8 = {6f 62 6a 77 73 2e 52 75 6e 20 63 65 72 74 75 74 69 6c 43 6f 6d 61 6e 64 20 26 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 90 02 14 20 26 20 43 6f 70 79 54 6f 90 02 04 2c 20 30 2c 20 54 72 75 65 90 00 } //01 00 
		$a_03_9 = {6f 62 6a 77 73 2e 52 75 6e 20 22 65 73 65 6e 74 75 74 6c 2e 65 78 65 20 2f 79 20 22 20 26 20 43 6f 70 79 54 6f 90 02 04 20 26 20 22 20 2f 64 20 22 20 26 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 90 02 14 20 26 20 22 20 2f 6f 22 2c 20 30 2c 20 54 72 75 65 90 00 } //01 00 
		$a_03_10 = {6f 62 6a 77 73 2e 52 75 6e 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 90 02 30 2c 20 30 2c 20 46 61 6c 73 65 90 00 } //01 00 
		$a_03_11 = {6f 62 6a 77 73 2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 22 20 26 20 41 6c 6c 55 73 65 72 73 50 72 6f 66 69 6c 65 20 26 20 90 02 10 2c 20 30 2c 20 46 61 6c 73 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}