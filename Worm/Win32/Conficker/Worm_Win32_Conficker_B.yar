
rule Worm_Win32_Conficker_B{
	meta:
		description = "Worm:Win32/Conficker.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f 31 89 45 90 01 01 89 55 90 01 01 ff 75 90 01 02 8b 55 90 01 01 2b c0 ff 25 90 00 } //01 00 
		$a_02_1 = {2b f6 0b c2 09 f1 a3 90 01 04 89 90 01 05 ff 35 90 01 04 58 50 68 00 90 01 03 ff 15 90 01 04 6a 90 01 01 a3 90 01 04 ff 15 90 01 04 90 13 ff 35 90 01 04 68 90 01 04 c7 05 90 01 08 ff 15 90 01 04 ff 35 90 01 04 a3 90 01 04 ff 15 90 01 04 0f 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_Conficker_B_2{
	meta:
		description = "Worm:Win32/Conficker.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 bc 50 ff 15 90 01 04 66 81 7d bc d9 07 77 11 0f 85 da 01 00 00 66 83 7d be 01 0f 82 cf 01 00 00 90 00 } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 25 73 2f 73 65 61 72 63 68 3f 71 3d 25 64 } //01 00  http://%s/search?q=%d
		$a_01_2 = {ff 53 4d 42 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5c 02 00 00 00 00 00 0c 00 02 4e 54 20 4c 4d 20 30 2e 31 32 00 00 00 00 00 49 ff 53 4d 42 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5c 02 00 00 00 00 0d ff 00 00 00 ff ff 02 00 5c 02 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 0b 00 00 00 4d 53 00 43 4c 49 45 4e 54 00 } //00 00 
	condition:
		any of ($a_*)
 
}