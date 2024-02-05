
rule Backdoor_Win32_Plugx_A{
	meta:
		description = "Backdoor:Win32/Plugx.A,SIGNATURE_TYPE_PEHSTR_EXT,19 00 14 00 0c 00 00 05 00 "
		
	strings :
		$a_01_0 = {80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64 74 } //05 00 
		$a_03_1 = {75 61 6c 41 c7 90 02 10 6c 6c 6f 63 90 00 } //05 00 
		$a_03_2 = {45 78 69 74 c7 85 90 01 01 ff ff ff 54 68 72 65 66 c7 85 90 01 01 ff ff ff 61 64 90 00 } //05 00 
		$a_01_3 = {03 d3 c1 e7 09 bb 44 44 44 44 } //05 00 
		$a_01_4 = {c7 06 47 55 4c 50 89 4e 14 8b 47 28 } //02 00 
		$a_01_5 = {5c 00 62 00 75 00 67 00 2e 00 6c 00 6f 00 67 00 00 00 } //02 00 
		$a_01_6 = {2f 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 4c 00 41 00 53 00 53 00 45 00 53 00 5c 00 46 00 41 00 53 00 54 00 5c 00 50 00 52 00 4f 00 58 00 59 00 } //02 00 
		$a_01_7 = {2f 75 70 64 61 74 65 3f 69 64 3d 25 38 2e 38 78 } //02 00 
		$a_01_8 = {5c 00 5c 00 2e 00 5c 00 50 00 49 00 50 00 45 00 5c 00 52 00 55 00 4e 00 5f 00 41 00 53 00 5f 00 55 00 53 00 45 00 52 00 } //02 00 
		$a_01_9 = {25 00 34 00 2e 00 34 00 64 00 2d 00 25 00 32 00 2e 00 32 00 64 00 2d 00 25 00 32 00 2e 00 32 00 64 00 20 00 25 00 32 00 2e 00 32 00 64 00 3a 00 25 00 32 00 2e 00 32 00 64 00 3a 00 25 00 32 00 2e 00 32 00 64 00 3a 00 } //02 00 
		$a_01_10 = {53 68 65 6c 6c 54 32 } //02 00 
		$a_01_11 = {54 65 6c 6e 65 74 54 32 } //00 00 
		$a_00_12 = {78 79 01 00 0b 00 0a 00 0d 00 } //00 02 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Plugx_A_2{
	meta:
		description = "Backdoor:Win32/Plugx.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 0d 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64 74 } //02 00 
		$a_03_1 = {75 61 6c 41 c7 85 90 01 01 ff ff ff 6c 6c 6f 63 90 00 } //02 00 
		$a_03_2 = {45 78 69 74 c7 85 90 01 01 ff ff ff 54 68 72 65 66 c7 85 90 01 01 ff ff ff 61 64 90 00 } //01 00 
		$a_01_3 = {58 50 6c 67 4c 6f 61 64 65 72 } //01 00 
		$a_01_4 = {58 50 6c 75 67 4b 65 79 4c 6f 67 67 65 72 } //01 00 
		$a_01_5 = {5c 73 68 65 6c 6c 63 6f 64 65 5c 73 68 65 6c 6c 63 6f 64 65 5c 58 50 6c 75 67 } //01 00 
		$a_01_6 = {2f 75 70 64 61 74 65 3f 69 64 3d 25 38 2e 38 78 } //01 00 
		$a_01_7 = {5c 00 5c 00 2e 00 5c 00 50 00 49 00 50 00 45 00 5c 00 52 00 55 00 4e 00 5f 00 41 00 53 00 5f 00 55 00 53 00 45 00 52 00 } //01 00 
		$a_01_8 = {5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 20 00 55 00 41 00 43 00 } //01 00 
		$a_01_9 = {2f 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 4c 00 41 00 53 00 53 00 45 00 53 00 5c 00 46 00 41 00 53 00 54 00 5c 00 50 00 52 00 4f 00 58 00 59 00 } //01 00 
		$a_01_10 = {6b 00 6c 00 2e 00 6c 00 6f 00 67 00 00 00 } //01 00 
		$a_01_11 = {25 00 73 00 5c 00 25 00 64 00 2e 00 70 00 6c 00 67 00 00 00 } //01 00 
		$a_01_12 = {5c 00 62 00 75 00 67 00 2e 00 6c 00 6f 00 67 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}