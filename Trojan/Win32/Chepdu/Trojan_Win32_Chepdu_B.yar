
rule Trojan_Win32_Chepdu_B{
	meta:
		description = "Trojan:Win32/Chepdu.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 4b 42 25 69 2e 65 78 65 00 } //01 00 
		$a_01_1 = {26 69 64 6b 65 79 3d 00 } //01 00  椦此祥=
		$a_01_2 = {26 65 66 6b 77 64 3d 00 } //01 00  攦武摷=
		$a_00_3 = {52 00 65 00 66 00 65 00 72 00 65 00 72 00 3a 00 20 00 25 00 68 00 73 00 0a 00 00 00 } //01 00 
		$a_01_4 = {64 70 65 63 68 75 00 } //01 00 
		$a_01_5 = {25 73 75 73 65 72 69 6e 69 74 7c 25 73 7c 25 73 00 } //01 00 
		$a_01_6 = {44 50 45 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00 
		$a_03_7 = {25 32 36 00 25 32 36 70 3d 90 02 04 25 33 66 70 3d 00 90 00 } //01 00 
		$a_01_8 = {7c 44 4c 3a 00 } //01 00 
		$a_01_9 = {25 32 36 70 3d 00 } //01 00  ㈥瀶=
		$a_00_10 = {4d 00 61 00 6e 00 79 00 42 00 6f 00 78 00 2e 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 00 00 } //03 00 
		$a_03_11 = {99 b9 00 7d 00 00 f7 f9 81 c2 a8 61 00 00 89 95 90 01 03 ff ff 15 90 01 04 6a 00 6a 26 90 00 } //02 00 
		$a_03_12 = {85 c0 74 1d 68 90 01 04 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 85 c0 74 07 33 c0 e9 90 01 02 00 00 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}