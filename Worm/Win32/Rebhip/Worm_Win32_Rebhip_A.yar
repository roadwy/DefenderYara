
rule Worm_Win32_Rebhip_A{
	meta:
		description = "Worm:Win32/Rebhip.A,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 28 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5f 78 5f 58 5f 55 50 44 41 54 45 5f 58 5f 78 5f } //0a 00  _x_X_UPDATE_X_x_
		$a_01_1 = {5f 78 5f 58 5f 50 41 53 53 57 4f 52 44 4c 49 53 54 5f 58 5f 78 5f } //0a 00  _x_X_PASSWORDLIST_X_x_
		$a_01_2 = {5f 78 5f 58 5f 42 4c 4f 43 4b 4d 4f 55 53 45 5f 58 5f 78 5f } //0a 00  _x_X_BLOCKMOUSE_X_x_
		$a_01_3 = {58 58 2d 2d 58 58 2d 2d 58 58 2e 74 78 74 } //01 00  XX--XX--XX.txt
		$a_01_4 = {4d 53 4e 2e 61 62 63 } //01 00  MSN.abc
		$a_01_5 = {46 49 52 45 46 4f 58 2e 61 62 63 } //01 00  FIREFOX.abc
		$a_01_6 = {49 45 4c 4f 47 49 4e 2e 61 62 63 } //01 00  IELOGIN.abc
		$a_01_7 = {49 45 50 41 53 53 2e 61 62 63 } //00 00  IEPASS.abc
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_Rebhip_A_2{
	meta:
		description = "Worm:Win32/Rebhip.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 54 1a ff 80 f2 90 01 01 88 54 18 ff 43 4e 75 e6 90 00 } //01 00 
		$a_03_1 = {81 ea 00 01 00 00 75 27 8d 85 fa fe ff ff 50 e8 90 01 04 6a 00 8d 45 fa 50 8d 85 fa fe ff ff 50 8b 43 04 50 8b 03 50 e8 90 00 } //01 00 
		$a_03_2 = {be 65 00 00 00 8b 1d 90 01 04 83 3b 00 74 32 8b 03 ba 6c ba 40 00 e8 90 01 04 74 24 90 00 } //01 00 
		$a_03_3 = {80 e3 02 80 e3 01 80 e3 04 33 c0 8a c3 50 56 e8 90 01 04 56 e8 90 01 04 83 f8 01 1b c0 40 88 45 fb 90 00 } //01 00 
		$a_03_4 = {eb 3d ff 36 8d 45 fc 8b d3 e8 90 01 04 ff 75 fc 68 90 01 04 53 e8 90 01 04 33 d2 52 50 8d 45 f8 e8 90 01 04 ff 75 f8 68 90 01 04 8b c6 ba 05 00 00 00 e8 90 01 04 83 c3 04 80 3b 00 75 be 90 00 } //01 00 
		$a_03_5 = {66 83 f8 01 75 74 6a 10 e8 90 01 04 66 85 c0 7d 34 8b 07 e8 90 01 04 85 c0 0f 8e 90 01 04 8b 07 e8 90 01 04 8b 17 80 7c 02 ff 7e 90 00 } //01 00 
		$a_01_6 = {75 48 6a 40 68 00 30 00 00 68 f4 01 00 00 6a 00 53 e8 } //00 00 
	condition:
		any of ($a_*)
 
}