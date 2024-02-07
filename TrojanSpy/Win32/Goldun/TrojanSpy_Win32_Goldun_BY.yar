
rule TrojanSpy_Win32_Goldun_BY{
	meta:
		description = "TrojanSpy:Win32/Goldun.BY,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0c 00 00 03 00 "
		
	strings :
		$a_01_0 = {5b 49 50 3d 2f 2f 2a 7e 7e 7e 7e 7e 2a 2f 2f 2f 2f 2a 44 41 54 45 54 49 4d 45 2a 2f 2f 5d 00 } //03 00 
		$a_01_1 = {5c 72 65 64 69 72 65 63 74 5f 66 61 6b 65 2e 74 78 74 00 } //03 00 
		$a_02_2 = {6c 69 2e 61 73 70 90 02 10 2f 61 63 63 74 2f 62 61 6c 61 6e 63 65 2e 61 73 70 90 02 10 2f 61 63 63 74 2f 63 6f 6e 66 69 72 6d 2e 61 73 90 00 } //01 00 
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 2d 67 6f 6c 64 2e 63 6f 6d 2f 61 63 63 74 2f } //01 00  https://www.e-gold.com/acct/
		$a_01_4 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 20 5b 55 52 4c 3d 00 } //01 00 
		$a_01_5 = {41 43 54 55 41 4c 5f 50 41 59 4d 45 4e 54 5f 4f 55 4e 43 45 53 20 76 61 6c 75 65 3d 22 } //01 00  ACTUAL_PAYMENT_OUNCES value="
		$a_01_6 = {50 61 79 65 65 5f 41 63 63 6f 75 6e 74 3d 25 73 26 41 6d 6f 75 6e 74 3d 25 73 26 50 41 59 5f 49 4e 3d } //01 00  Payee_Account=%s&Amount=%s&PAY_IN=
		$a_01_7 = {69 64 3d 25 30 38 6c 58 25 30 38 6c 58 26 69 70 3d 25 73 26 74 69 74 6c 65 3d 25 73 26 75 72 6c 3d 25 73 26 64 61 74 61 3d } //01 00  id=%08lX%08lX&ip=%s&title=%s&url=%s&data=
		$a_01_8 = {41 63 63 6f 75 6e 74 49 44 3d 25 73 26 50 61 73 73 50 68 72 61 73 65 3d 25 73 26 41 6d 6f 75 6e 74 3d 25 73 26 45 6d 61 69 6c 3d 25 73 } //01 00  AccountID=%s&PassPhrase=%s&Amount=%s&Email=%s
		$a_02_9 = {26 50 41 59 4d 45 4e 54 5f 55 4e 49 54 53 3d 90 02 08 26 50 41 59 4d 45 4e 54 5f 4d 45 54 41 4c 5f 49 44 3d 90 02 08 26 50 41 59 45 52 5f 41 43 43 4f 55 4e 54 3d 90 00 } //01 00 
		$a_01_10 = {69 63 71 2e 70 68 70 3f 74 65 78 74 3d 00 } //01 00 
		$a_01_11 = {67 6f 6c 64 2e 70 68 70 3f 69 64 3d } //00 00  gold.php?id=
	condition:
		any of ($a_*)
 
}