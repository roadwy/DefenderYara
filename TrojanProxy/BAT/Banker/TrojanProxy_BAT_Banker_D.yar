
rule TrojanProxy_BAT_Banker_D{
	meta:
		description = "TrojanProxy:BAT/Banker.D,SIGNATURE_TYPE_PEHSTR_EXT,ffffffdc 00 ffffffd2 00 0e 00 00 64 00 "
		
	strings :
		$a_01_0 = {2e 00 74 00 75 00 64 00 6f 00 65 00 63 00 6f 00 6c 00 6f 00 67 00 79 00 2e 00 63 00 6f 00 6d 00 22 00 3b 00 } //32 00 
		$a_01_1 = {77 00 2e 00 69 00 64 00 65 00 6e 00 74 00 69 00 74 00 79 00 6d 00 75 00 73 00 69 00 63 00 2e 00 63 00 6f 00 2e 00 75 00 6b 00 2f 00 } //32 00 
		$a_01_2 = {64 00 69 00 73 00 61 00 73 00 74 00 65 00 72 00 6a 00 6f 00 75 00 72 00 6e 00 61 00 6c 00 2e 00 6e 00 65 00 74 00 2f 00 63 00 68 00 65 00 63 00 6b 00 2e 00 70 00 68 00 70 00 } //28 00 
		$a_01_3 = {76 00 61 00 72 00 20 00 69 00 70 00 73 00 61 00 6e 00 74 00 61 00 20 00 3d 00 20 00 22 00 50 00 52 00 4f 00 58 00 59 00 } //28 00 
		$a_01_4 = {69 00 70 00 70 00 61 00 79 00 70 00 61 00 6c 00 20 00 3d 00 20 00 22 00 50 00 52 00 4f 00 58 00 59 00 } //1e 00 
		$a_01_5 = {6c 00 2d 00 77 00 6f 00 72 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 61 00 6c 00 6c 00 65 00 72 00 69 00 65 00 73 00 2f 00 6c 00 61 00 66 00 61 00 72 00 65 00 77 00 65 00 6c 00 6c 00 } //1e 00 
		$a_01_6 = {5c 00 78 00 36 00 32 00 5c 00 78 00 36 00 31 00 5c 00 78 00 36 00 65 00 5c 00 78 00 36 00 33 00 5c 00 78 00 36 00 66 00 5c 00 78 00 36 00 34 00 5c 00 78 00 36 00 66 00 5c 00 78 00 36 00 32 00 5c 00 78 00 37 00 32 00 5c 00 78 00 36 00 31 00 5c 00 78 00 37 00 33 00 5c 00 78 00 36 00 39 00 5c 00 78 00 36 00 63 00 } //1e 00 
		$a_01_7 = {70 00 6f 00 73 00 31 00 20 00 3d 00 20 00 22 00 2a 00 5c 00 78 00 36 00 32 00 22 00 2b 00 22 00 22 00 2b 00 22 00 5c 00 78 00 36 00 32 00 2a 00 } //1e 00 
		$a_01_8 = {69 00 74 00 61 00 31 00 20 00 3d 00 20 00 22 00 2a 00 5c 00 78 00 36 00 39 00 5c 00 78 00 37 00 34 00 5c 00 78 00 36 00 31 00 5c 00 78 00 37 00 35 00 2a 00 } //1e 00 
		$a_01_9 = {73 00 61 00 6e 00 74 00 61 00 32 00 20 00 3d 00 20 00 22 00 6e 00 64 00 65 00 72 00 2a 00 } //14 00 
		$a_01_10 = {70 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 63 00 2e 00 6a 00 73 00 70 00 } //14 00 
		$a_01_11 = {68 00 6f 00 74 00 65 00 6c 00 63 00 6f 00 73 00 74 00 61 00 2f 00 63 00 68 00 65 00 63 00 6b 00 2e 00 70 00 68 00 70 00 } //14 00 
		$a_01_12 = {61 00 74 00 6f 00 6d 00 69 00 63 00 2f 00 63 00 68 00 65 00 63 00 6b 00 2e 00 70 00 68 00 70 00 } //0a 00 
		$a_01_13 = {26 00 6e 00 65 00 74 00 43 00 61 00 72 00 64 00 3d 00 } //00 00 
		$a_00_14 = {87 10 00 00 7b 35 02 2d d9 66 04 de 2c f6 7b 80 60 42 00 00 87 10 00 00 a7 8a 2b 35 62 08 44 e0 76 21 c2 e8 f0 42 00 00 87 10 00 00 16 28 ab 37 26 f6 d2 01 a2 74 c1 09 10 4f 00 00 87 10 00 00 87 9a f5 37 3c 9a } //c9 70 
	condition:
		any of ($a_*)
 
}