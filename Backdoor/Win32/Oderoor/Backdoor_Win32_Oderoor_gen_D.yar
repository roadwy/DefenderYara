
rule Backdoor_Win32_Oderoor_gen_D{
	meta:
		description = "Backdoor:Win32/Oderoor.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 11 00 00 04 00 "
		
	strings :
		$a_01_0 = {68 56 52 41 48 50 e8 } //05 00 
		$a_03_1 = {8d 7d f8 a5 66 a5 a4 33 db 8a c3 04 61 8d 4c 1d 90 01 01 88 41 90 01 01 8b c3 99 6a 06 5e f7 fe 83 fb 0a 8a 44 15 f8 88 01 7d 07 8a c3 04 30 88 41 90 01 01 43 83 fb 1a 7c 90 00 } //05 00 
		$a_01_2 = {b9 ea d8 00 00 f7 f1 6a 06 6a 01 6a 02 81 c2 10 27 00 00 0f b7 f2 } //03 00 
		$a_03_3 = {8a 00 3c 2a 74 90 01 01 3c 2b 74 90 01 01 3c 3f 74 90 00 } //02 00 
		$a_03_4 = {8b 87 1c 04 00 00 0f be 00 85 c0 74 90 01 01 83 f8 7c 74 90 01 01 83 f8 29 74 90 00 } //04 00 
		$a_03_5 = {6a 01 6a 03 6a 02 ff 15 90 02 40 48 48 48 48 ff 15 90 00 } //04 00 
		$a_01_6 = {3d 6f 7a 6c 6d 74 04 33 c0 } //03 00 
		$a_03_7 = {8b 07 80 38 23 75 90 01 01 81 78 01 65 6e 63 23 75 90 00 } //06 00 
		$a_03_8 = {b8 00 00 00 00 0f a2 01 06 01 56 04 b8 01 00 00 00 0f a2 31 06 31 56 04 b8 03 00 00 00 0f a2 31 16 31 4e 04 68 04 01 00 00 8d 85 90 01 03 ff 50 ff 15 90 01 04 8a 8d 90 01 03 ff 0f b6 c1 2c 61 b2 19 3a d0 90 00 } //04 00 
		$a_01_9 = {6d 72 74 73 74 75 62 2e 65 78 65 00 6d 72 74 2e 65 78 65 00 } //03 00 
		$a_01_10 = {67 72 6f 00 6d 6f 63 00 74 65 6e } //03 00 
		$a_01_11 = {74 65 6e 00 6d 6f 63 00 67 72 6f 00 6f 63 00 } //02 00 
		$a_01_12 = {6e 6d 74 73 00 00 00 00 61 6f 65 69 79 75 00 } //02 00 
		$a_01_13 = {61 6f 65 69 79 75 00 00 6e 6d 74 73 00 } //01 00 
		$a_01_14 = {25 64 2c 25 64 2c 25 73 2c 25 73 2c 25 73 0a 00 25 64 2c 25 64 2c 25 73 0a 00 } //02 00 
		$a_01_15 = {43 63 73 70 78 58 75 69 64 25 } //02 00  CcspxXuid%
		$a_01_16 = {63 43 64 69 70 73 75 78 58 25 } //00 00  cCdipsuxX%
	condition:
		any of ($a_*)
 
}