
rule Trojan_Win64_Depriz_G_dha{
	meta:
		description = "Trojan:Win64/Depriz.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 0c 17 ff c0 48 83 c2 02 66 83 e9 90 01 01 66 89 4a fe 83 f8 90 01 01 72 e9 90 00 } //01 00 
		$a_00_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 22 00 70 00 69 00 6e 00 67 00 20 00 2d 00 6e 00 20 00 33 00 30 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 3e 00 6e 00 75 00 6c 00 20 00 26 00 26 00 20 00 73 00 63 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 25 00 73 00 20 00 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 3d 00 20 00 22 00 25 00 73 00 20 00 4c 00 6f 00 63 00 61 00 6c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 22 00 20 00 26 00 26 00 20 00 70 00 69 00 6e 00 67 00 20 00 2d 00 6e 00 20 00 31 00 30 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 3e 00 6e 00 75 00 6c 00 20 00 26 00 26 00 20 00 73 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 25 00 73 00 } //01 00 
		$a_00_2 = {54 00 68 00 65 00 20 00 4d 00 61 00 69 00 6e 00 74 00 65 00 6e 00 61 00 63 00 65 00 20 00 48 00 6f 00 73 00 74 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 69 00 73 00 20 00 68 00 6f 00 73 00 74 00 65 00 64 00 20 00 69 00 6e 00 20 00 74 00 68 00 65 00 20 00 4c 00 53 00 41 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 20 00 54 00 68 00 65 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 73 00 20 00 6b 00 65 00 79 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 69 00 73 00 6f 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 74 00 6f 00 20 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 20 00 6b 00 65 00 79 00 73 00 } //01 00 
		$a_00_3 = {61 00 76 00 65 00 72 00 66 00 69 00 78 00 32 00 68 00 38 00 32 00 36 00 64 00 5f 00 6e 00 6f 00 61 00 76 00 65 00 72 00 69 00 72 00 } //01 00 
		$a_00_4 = {4d 00 61 00 69 00 6e 00 74 00 65 00 6e 00 61 00 63 00 65 00 53 00 72 00 76 00 36 00 34 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_5 = {4d 00 61 00 69 00 6e 00 74 00 65 00 6e 00 61 00 63 00 65 00 53 00 72 00 76 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_6 = {5c 00 69 00 6e 00 66 00 5c 00 6d 00 64 00 6d 00 6e 00 69 00 73 00 35 00 74 00 51 00 31 00 2e 00 70 00 6e 00 66 00 } //01 00 
		$a_00_7 = {5c 00 69 00 6e 00 66 00 5c 00 61 00 76 00 65 00 72 00 62 00 68 00 5f 00 6e 00 6f 00 61 00 76 00 2e 00 70 00 6e 00 66 00 } //01 00 
		$a_01_8 = {5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 6b 65 79 38 38 35 34 33 32 31 2e 70 75 62 } //00 00 
		$a_00_9 = {5d 04 00 } //00 e5 
	condition:
		any of ($a_*)
 
}