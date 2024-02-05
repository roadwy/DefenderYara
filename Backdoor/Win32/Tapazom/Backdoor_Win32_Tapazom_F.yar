
rule Backdoor_Win32_Tapazom_F{
	meta:
		description = "Backdoor:Win32/Tapazom.F,SIGNATURE_TYPE_PEHSTR_EXT,40 01 ffffffdc 00 06 00 00 64 00 "
		
	strings :
		$a_01_0 = {eb 60 83 7d ec ff 75 0a 83 7d e8 ff 75 04 b3 01 eb 60 80 7d f7 0e 74 5a 80 7d f7 0a 74 22 80 7d f7 0d 74 1c } //64 00 
		$a_03_1 = {8a 03 33 d2 8a d0 25 ff 00 00 00 d1 e8 2b d0 33 c0 8a 44 13 01 a3 90 01 02 40 00 33 c0 8a 03 33 d2 8a 13 d1 ea 2b c2 0f b6 04 03 90 00 } //32 00 
		$a_01_2 = {6d 6d 7a 6f 2e 64 79 6e 64 6e 73 2e 6f 72 67 3a 31 31 34 33 } //32 00 
		$a_01_3 = {0b 49 6e 63 6c 6f 75 64 2e 65 78 65 } //14 00 
		$a_01_4 = {48 49 44 2d 44 65 76 69 63 65 } //14 00 
		$a_01_5 = {6d 7a 73 72 36 34 2e 64 6c 6c } //00 00 
		$a_00_6 = {5d 04 00 00 1d d4 02 80 5c 21 00 00 1e d4 02 80 00 00 01 00 27 00 0b 00 cb 01 4e 61 72 69 6c 6f 67 2e 41 00 00 01 40 05 82 5f 00 04 00 80 10 00 00 19 b3 6e d6 a4 41 9b a4 2c 1f f1 9b a1 01 00 80 5d 04 00 00 1e } //d4 02 
	condition:
		any of ($a_*)
 
}