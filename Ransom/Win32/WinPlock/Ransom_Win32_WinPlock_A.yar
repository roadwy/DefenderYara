
rule Ransom_Win32_WinPlock_A{
	meta:
		description = "Ransom:Win32/WinPlock.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 61 00 79 00 20 00 4f 00 4b 00 21 00 20 00 43 00 68 00 61 00 6e 00 67 00 65 00 57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 20 00 61 00 6e 00 64 00 20 00 64 00 65 00 63 00 6f 00 64 00 65 00 21 00 } //01 00 
		$a_01_1 = {57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 20 00 63 00 68 00 61 00 6e 00 67 00 65 00 64 00 00 00 } //01 00 
		$a_01_2 = {57 00 6f 00 72 00 6b 00 5c 00 63 00 6c 00 6f 00 63 00 6b 00 5c 00 50 00 43 00 6c 00 6f 00 63 00 6b 00 2e 00 76 00 62 00 70 00 00 00 } //01 00 
		$a_01_3 = {53 00 74 00 61 00 72 00 74 00 20 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 00 00 } //01 00 
		$a_01_4 = {55 00 41 00 43 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 22 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 22 00 2c 00 20 00 22 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 00 00 } //01 00 
		$a_01_5 = {2e 00 33 00 66 00 72 00 7c 00 2e 00 61 00 63 00 63 00 64 00 62 00 7c 00 2e 00 61 00 69 00 7c 00 2e 00 61 00 72 00 77 00 7c 00 2e 00 62 00 61 00 79 00 7c 00 2e 00 63 00 64 00 72 00 7c 00 2e 00 63 00 65 00 72 00 7c 00 2e 00 63 00 72 00 32 00 7c 00 2e 00 63 00 72 00 74 00 7c 00 2e 00 63 00 72 00 77 00 7c 00 00 00 } //01 00 
		$a_01_6 = {77 00 69 00 6e 00 63 00 6c 00 77 00 70 00 2e 00 6a 00 70 00 67 00 00 00 } //01 00 
		$a_01_7 = {6f 00 6e 00 69 00 6f 00 6e 00 5f 00 63 00 61 00 62 00 5f 00 69 00 4b 00 6e 00 6f 00 77 00 53 00 68 00 69 00 74 00 3d 00 } //01 00 
		$a_01_8 = {5c 00 65 00 6e 00 63 00 5f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 00 00 } //01 00 
		$a_01_9 = {5c 00 63 00 6c 00 6f 00 63 00 6b 00 5f 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 00 00 } //01 00 
		$a_01_10 = {45 00 72 00 72 00 6f 00 72 00 20 00 6f 00 70 00 65 00 6e 00 20 00 66 00 69 00 6c 00 65 00 20 00 6c 00 69 00 73 00 74 00 21 00 20 00 53 00 6f 00 72 00 72 00 79 00 2e 00 2e 00 00 00 } //00 00 
		$a_00_11 = {5d 04 00 00 } //9e 2e 
	condition:
		any of ($a_*)
 
}