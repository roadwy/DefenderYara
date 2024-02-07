
rule Backdoor_Win32_Poison_E{
	meta:
		description = "Backdoor:Win32/Poison.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 e3 03 83 fb 00 75 03 83 ee 10 ad 33 07 ab 43 e2 ee } //01 00 
		$a_01_1 = {8b 46 3c 8b 54 06 78 03 d6 8b 4a 18 8b 5a 20 03 de e3 35 49 8b 34 8b 03 75 08 33 ff 33 c0 fc ac 84 c0 74 07 c1 cf 0d 03 f8 eb f4 } //01 00 
		$a_01_2 = {8b 75 08 81 e6 00 00 ff ff 66 ad 4e 4e 3d 4d 5a 00 00 74 08 81 ee 00 00 01 00 eb ed } //00 00 
		$a_00_3 = {78 } //76 01  x
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Poison_E_2{
	meta:
		description = "Backdoor:Win32/Poison.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {e8 1b 00 00 00 43 4f 4e 4e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31 } //01 00 
		$a_02_1 = {e8 09 00 00 00 61 64 76 61 70 69 33 32 00 ff 90 01 04 ff 90 03 01 01 89 09 90 01 04 ff e8 06 00 00 00 6e 74 64 6c 6c 00 ff 90 01 04 ff 89 90 01 04 ff e8 07 00 00 00 75 73 65 72 33 32 00 ff 90 00 } //02 00 
		$a_01_2 = {81 bd 30 fa ff ff 63 6b 73 3d 75 13 c7 85 30 fa ff ff 74 74 70 3d c6 86 ef 0a 00 00 02 eb 11 c7 85 30 fa ff ff 63 6b 73 3d c6 86 ef 0a 00 00 01 } //02 00 
		$a_02_3 = {56 8d 86 6b 09 00 00 50 8d 86 45 01 00 00 50 ff 96 fd 00 00 00 e8 90 01 01 00 00 00 77 73 32 5f 33 32 00 58 50 ff 96 9d 00 00 00 90 01 01 86 c3 0a 00 00 e8 3a 00 00 00 e1 60 90 00 } //03 00 
		$a_02_4 = {e8 08 00 00 00 61 64 76 70 61 63 6b 00 ff 95 90 01 02 ff ff 68 6b 37 04 7e 50 6a 00 e8 90 01 03 ff 6a 00 6a 00 ff d0 90 03 01 01 88 08 85 90 01 02 ff ff 68 0e 03 e5 e6 ff b5 90 01 02 ff ff 6a 00 e8 90 01 03 ff 0b c0 75 12 68 94 2c d5 87 ff b5 90 01 02 ff ff 6a 00 e8 90 01 03 ff 89 85 90 01 02 ff ff 90 00 } //01 00 
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 56 } //00 00  SOFTWARE\Classes\http\shell\open\commandV
	condition:
		any of ($a_*)
 
}