
rule Backdoor_Win32_Poison_BN{
	meta:
		description = "Backdoor:Win32/Poison.BN,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 2e 3b 37 2e 35 47 46 } //01 00 
		$a_01_1 = {5b 00 43 00 52 00 45 00 41 00 54 00 45 00 2e 00 4e 00 45 00 57 00 20 00 3d 00 20 00 55 00 53 00 45 00 52 00 20 00 4e 00 41 00 4d 00 45 00 5d 00 } //01 00 
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00 
		$a_01_3 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_4 = {63 00 3a 00 5c 00 72 00 65 00 63 00 6f 00 72 00 64 00 2e 00 64 00 61 00 74 00 } //01 00 
		$a_01_5 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_6 = {7b 00 62 00 61 00 63 00 6b 00 73 00 70 00 61 00 63 00 65 00 7d 00 } //01 00 
		$a_01_7 = {7b 00 53 00 63 00 72 00 6f 00 6c 00 6c 00 4c 00 6f 00 63 00 6b 00 7d 00 } //01 00 
		$a_01_8 = {7b 00 50 00 72 00 69 00 6e 00 74 00 53 00 63 00 72 00 65 00 65 00 6e 00 7d 00 } //00 00 
	condition:
		any of ($a_*)
 
}