
rule PWS_Win32_Reder_B{
	meta:
		description = "PWS:Win32/Reder.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {3b df 89 5d 90 01 01 7d 90 01 01 8b 45 90 01 01 8a 04 06 88 04 1e 68 90 01 04 8d 45 90 01 01 50 ff 15 90 01 04 83 45 90 01 01 03 43 39 7d 90 01 01 7c de 90 00 } //02 00 
		$a_01_1 = {45 4d 41 49 4c 3a 20 25 73 0a 50 41 53 53 20 3a 20 25 73 } //01 00 
		$a_01_2 = {21 74 69 63 6b 69 74 21 } //01 00  !tickit!
		$a_01_3 = {21 62 6c 6f 63 6b 21 } //01 00  !block!
		$a_01_4 = {21 73 63 72 65 65 6e 21 } //01 00  !screen!
		$a_01_5 = {21 72 65 64 65 72 21 } //01 00  !reder!
		$a_01_6 = {21 6b 69 6c 6c 21 } //01 00  !kill!
		$a_01_7 = {32 32 30 64 35 63 63 31 } //00 00  220d5cc1
	condition:
		any of ($a_*)
 
}