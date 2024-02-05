
rule Worm_Win32_Conficker_gen_A{
	meta:
		description = "Worm:Win32/Conficker.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {f7 21 a2 90 00 2e 64 6c 6c 13 ff e7 ff cd 5c 47 6c 6f 62 61 6c 5c 25 75 2d 25 75 42 e9 4c 30 39 } //01 00 
		$a_03_1 = {59 59 85 c0 75 11 ff 75 08 ff 15 90 01 04 59 3d c8 00 00 00 76 16 83 4d fc ff 6a 57 90 00 } //01 00 
		$a_03_2 = {76 18 8b 06 03 c7 80 30 90 01 01 8d 45 90 01 01 50 47 e8 90 01 04 03 c3 3b f8 59 72 e8 8b 06 90 00 } //01 00 
		$a_03_3 = {6a 0e 8d 87 90 01 02 00 00 68 90 01 04 50 e8 90 01 02 00 00 8d 87 90 01 02 00 00 66 c7 00 41 00 90 00 } //01 00 
		$a_01_4 = {c6 46 40 eb c6 46 41 02 c6 46 44 eb c6 46 45 58 eb 3a } //00 00 
	condition:
		any of ($a_*)
 
}