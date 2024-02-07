
rule Backdoor_Win32_Escad_F_dha{
	meta:
		description = "Backdoor:Win32/Escad.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 72 65 67 6b 5d 00 00 5b 77 6f 77 36 34 5d 00 5b 6e 74 66 73 5d 00 00 5b 64 69 72 61 5d 00 00 5b 64 69 72 72 5d 00 } //01 00 
		$a_01_1 = {77 65 76 74 75 74 69 6c 2e 65 78 65 20 63 6c 20 22 25 73 22 20 2f 62 75 3a 22 25 73 22 00 } //01 00 
		$a_01_2 = {25 73 5c 66 78 25 69 25 69 2e 62 61 74 00 } //00 00 
		$a_00_3 = {78 95 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Escad_F_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 e2 34 80 c2 2d 88 54 24 10 8b d1 f7 da 1a d2 80 e2 37 80 c2 2d 88 54 24 11 8b d0 80 e2 02 f6 da 1a d2 80 e2 3b 80 c2 2d f7 d9 1a c9 24 04 80 e1 45 88 54 24 12 80 c1 2d } //01 00 
		$a_01_1 = {25 34 64 2f 25 32 64 2f 25 32 64 5f 25 32 64 3a 25 32 64 } //01 00  %4d/%2d/%2d_%2d:%2d
		$a_01_2 = {25 73 20 25 2d 32 30 73 20 25 31 30 6c 75 20 25 73 } //01 00  %s %-20s %10lu %s
		$a_01_3 = {5f 71 75 69 74 00 00 00 5f 65 78 65 00 00 00 00 5f 70 75 74 00 00 00 00 5f 67 6f 74 00 } //00 00 
		$a_00_4 = {78 cd } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Escad_F_dha_3{
	meta:
		description = "Backdoor:Win32/Escad.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {25 32 64 3a 25 32 64 00 25 73 20 25 2d 32 30 73 20 25 31 30 6c 75 20 25 73 0a 00 00 7c 00 00 00 5f 64 69 72 00 00 00 00 5f 67 65 74 00 00 00 00 5f 67 6f 74 00 00 00 00 5f 70 75 74 00 00 00 00 5f 65 78 65 00 00 00 00 5f 71 75 69 74 00 00 00 } //02 00 
		$a_00_1 = {67 6f 00 00 74 69 00 00 73 68 00 00 66 73 00 00 74 73 00 00 64 6c 00 00 64 75 00 00 64 65 00 00 63 6d 00 00 63 75 00 00 65 78 00 00 25 2e 32 58 } //01 00 
		$a_01_2 = {8a 14 39 80 c2 03 0f b6 c2 83 f0 03 8b d0 c1 ea 03 c0 e0 05 0a d0 88 14 39 41 3b cb 7c e2 } //01 00 
		$a_01_3 = {d0 f9 ff ff 7a 69 1b df } //01 00 
		$a_01_4 = {d0 f9 ff ff 92 e0 7c a3 } //00 00 
		$a_00_5 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}