
rule TrojanSpy_Win32_Rorpesafi_A{
	meta:
		description = "TrojanSpy:Win32/Rorpesafi.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 04 00 "
		
	strings :
		$a_01_0 = {64 72 69 76 65 72 73 2e 78 33 32 00 ff ff ff ff 09 00 00 00 73 72 74 66 6c 2e 65 78 65 } //02 00 
		$a_01_1 = {73 61 6e 65 6b 73 75 70 65 72 33 33 68 64 69 6e 6a 72 } //02 00  saneksuper33hdinjr
		$a_01_2 = {77 6a 36 33 6a 64 64 39 30 38 33 34 35 30 32 } //02 00  wj63jdd90834502
		$a_01_3 = {73 69 73 6d 66 6f 72 61 6c 2e 73 79 73 } //02 00  sismforal.sys
		$a_01_4 = {47 61 6d 46 6f 72 57 69 6e } //02 00  GamForWin
		$a_01_5 = {73 76 63 68 6f 73 74 33 32 2e 65 78 65 00 00 00 2f 69 6e 73 74 61 6c 6c 20 2f 53 49 4c 45 4e 54 } //01 00 
		$a_01_6 = {42 61 69 64 75 41 6e 54 72 61 79 20 2e 65 78 65 } //01 00  BaiduAnTray .exe
		$a_01_7 = {4b 65 79 48 6f 6f 6b 44 4c 4c 2e 64 6c 6c } //01 00  KeyHookDLL.dll
		$a_01_8 = {5a 61 70 75 73 6b 56 56 56 } //00 00  ZapuskVVV
		$a_00_9 = {5d 04 00 00 } //2c 43 
	condition:
		any of ($a_*)
 
}