
rule TrojanSpy_Win32_Usteal_F{
	meta:
		description = "TrojanSpy:Win32/Usteal.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 69 6e 70 63 6b 67 2e 65 78 65 } //01 00  winpckg.exe
		$a_01_1 = {72 61 69 6e 79 5f 64 61 79 5f 74 6f 64 61 79 } //01 00  rainy_day_today
		$a_01_2 = {69 6e 73 74 61 6c 6c 2e 70 63 6b } //01 00  install.pck
		$a_01_3 = {52 61 69 6e 79 20 4b 65 79 6c 6f 67 67 65 72 20 4c 6f 67 73 20 5b 20 25 73 20 5d } //00 00  Rainy Keylogger Logs [ %s ]
	condition:
		any of ($a_*)
 
}