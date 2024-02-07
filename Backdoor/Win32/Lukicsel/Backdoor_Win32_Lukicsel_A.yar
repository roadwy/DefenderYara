
rule Backdoor_Win32_Lukicsel_A{
	meta:
		description = "Backdoor:Win32/Lukicsel.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 8a 09 32 ca 8b 5d f8 88 0b ff 45 fc ff 45 f8 48 75 eb } //02 00 
		$a_03_1 = {7c 19 43 e8 90 01 04 8b 55 fc 32 02 8b 55 f8 88 02 ff 45 fc ff 45 f8 4b 75 e8 90 00 } //02 00 
		$a_03_2 = {b8 b8 88 00 00 e8 90 01 04 66 05 88 13 50 e8 90 00 } //02 00 
		$a_03_3 = {48 0f 85 c0 00 00 00 8d 45 e4 b9 02 00 00 00 ba 01 00 00 00 e8 90 01 04 8d 45 e0 50 8b 55 e4 b8 90 01 04 e8 90 00 } //02 00 
		$a_01_4 = {6e 65 74 3d 67 6e 75 74 65 6c 6c 61 00 00 00 00 ff ff ff ff 05 00 00 00 67 65 74 3d 31 00 00 00 ff ff ff ff 0f 00 00 00 63 6c 69 65 6e 74 3d 6c 69 6d 65 77 69 72 65 00 ff ff ff ff 02 00 00 00 48 7c 00 } //01 00 
		$a_01_5 = {2f 73 6b 75 6c 6c 73 2e 70 68 70 } //01 00  /skulls.php
		$a_01_6 = {2f 67 77 63 2e 70 68 70 } //00 00  /gwc.php
	condition:
		any of ($a_*)
 
}