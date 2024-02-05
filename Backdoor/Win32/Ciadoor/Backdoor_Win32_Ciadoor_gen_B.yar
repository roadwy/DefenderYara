
rule Backdoor_Win32_Ciadoor_gen_B{
	meta:
		description = "Backdoor:Win32/Ciadoor.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,19 00 15 00 14 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 00 63 00 74 00 69 00 76 00 65 00 20 00 53 00 65 00 74 00 75 00 70 00 5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 20 00 43 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 73 00 5c 00 7b 00 34 00 34 00 42 00 42 00 41 00 38 00 35 00 35 00 2d 00 43 00 43 00 35 00 31 00 2d 00 31 00 31 00 43 00 46 00 2d 00 41 00 41 00 46 00 41 00 2d 00 30 00 30 00 41 00 41 00 30 00 30 00 43 00 37 00 31 00 37 00 30 00 53 00 7d 00 } //05 00 
		$a_01_1 = {43 00 49 00 41 00 20 00 4e 00 6f 00 74 00 69 00 66 00 79 00 } //01 00 
		$a_01_2 = {25 00 42 00 42 00 45 00 47 00 } //01 00 
		$a_01_3 = {25 00 45 00 45 00 4e 00 44 00 } //01 00 
		$a_01_4 = {25 00 42 00 4d 00 50 00 54 00 } //01 00 
		$a_01_5 = {25 00 45 00 54 00 50 00 54 00 } //01 00 
		$a_01_6 = {25 00 42 00 4b 00 50 00 54 00 } //01 00 
		$a_01_7 = {25 00 45 00 4b 00 50 00 54 00 } //01 00 
		$a_01_8 = {25 00 42 00 50 00 41 00 73 00 4c 00 } //01 00 
		$a_01_9 = {25 00 45 00 50 00 41 00 73 00 4c 00 } //01 00 
		$a_01_10 = {25 00 42 00 56 00 49 00 43 00 } //01 00 
		$a_01_11 = {25 00 45 00 56 00 49 00 43 00 } //01 00 
		$a_01_12 = {25 00 42 00 52 00 47 00 52 00 } //01 00 
		$a_01_13 = {25 00 45 00 52 00 47 00 52 00 } //01 00 
		$a_01_14 = {25 00 42 00 52 00 47 00 73 00 4c 00 } //01 00 
		$a_01_15 = {26 00 70 00 6f 00 72 00 74 00 3d 00 } //01 00 
		$a_01_16 = {26 00 76 00 69 00 63 00 6e 00 61 00 6d 00 65 00 3d 00 } //01 00 
		$a_01_17 = {26 00 75 00 73 00 72 00 6e 00 61 00 6d 00 65 00 3d 00 } //01 00 
		$a_01_18 = {26 00 73 00 65 00 72 00 76 00 65 00 72 00 3d 00 } //01 00 
		$a_01_19 = {26 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}