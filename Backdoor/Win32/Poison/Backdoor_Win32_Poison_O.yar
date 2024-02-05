
rule Backdoor_Win32_Poison_O{
	meta:
		description = "Backdoor:Win32/Poison.O,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 69 6e 45 78 65 63 } //01 00 
		$a_00_1 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //01 00 
		$a_00_2 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //01 00 
		$a_00_3 = {47 65 74 53 68 6f 72 74 50 61 74 68 4e 61 6d 65 41 } //01 00 
		$a_00_4 = {47 65 74 46 69 6c 65 54 69 6d 65 } //01 00 
		$a_00_5 = {47 65 74 46 69 6c 65 53 69 7a 65 } //01 00 
		$a_00_6 = {57 72 69 74 65 46 69 6c 65 } //01 00 
		$a_01_7 = {5d 00 00 00 5b 53 59 53 54 45 4d 33 32 5d 00 00 5c 00 00 00 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 00 00 00 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 00 00 5c 50 61 72 61 6d 65 74 65 72 73 00 53 65 72 76 69 63 65 44 6c 6c 00 00 44 65 73 63 72 69 70 74 69 6f 6e 00 4c 69 6e 6b 4e 61 6d 65 00 00 00 00 63 6d 64 20 2f 63 20 64 } //00 00 
	condition:
		any of ($a_*)
 
}