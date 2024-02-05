
rule Backdoor_Win32_Lecna_dha{
	meta:
		description = "Backdoor:Win32/Lecna!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 03 c1 8a 10 80 f2 71 02 d1 80 c2 50 41 3b 4c 24 08 88 10 7c e7 } //01 00 
		$a_01_1 = {25 73 57 69 6e 4e 54 25 64 2e 25 64 5d 00 00 00 25 73 57 69 6e 32 30 30 33 5d 00 00 25 73 57 69 6e 58 50 5d 00 00 00 00 25 73 57 69 6e 32 4b 5d 00 00 } //01 00 
		$a_01_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 53 4a 5a 4a 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 33 32 29 } //00 00 
		$a_00_3 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}