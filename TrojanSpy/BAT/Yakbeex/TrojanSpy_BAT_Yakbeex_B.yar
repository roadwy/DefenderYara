
rule TrojanSpy_BAT_Yakbeex_B{
	meta:
		description = "TrojanSpy:BAT/Yakbeex.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {66 75 76 69 6f 6e 2e 65 78 65 00 } //fuvion.exe  01 00 
		$a_80_1 = {47 61 6d 69 6e 67 20 4d 6f 75 73 65 20 44 72 69 76 65 72 00 } //Gaming Mouse Driver  01 00 
		$a_01_2 = {4d 69 6f 43 61 72 64 00 } //01 00  楍䍯牡d
		$a_01_3 = {44 6f 6d 61 69 6e 55 70 44 6f 77 6e 00 } //01 00 
		$a_01_4 = {37 00 65 00 38 00 61 00 35 00 30 00 34 00 38 00 2d 00 63 00 64 00 39 00 30 00 2d 00 34 00 62 00 62 00 64 00 2d 00 62 00 30 00 63 00 38 00 2d 00 35 00 37 00 63 00 39 00 62 00 30 00 65 00 32 00 64 00 61 00 37 00 30 00 00 00 } //00 00 
		$a_00_5 = {78 a7 00 } //00 05 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_BAT_Yakbeex_B_2{
	meta:
		description = "TrojanSpy:BAT/Yakbeex.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 20 00 74 00 79 00 70 00 65 00 64 00 3a 00 } //01 00  Keystrokes typed:
		$a_01_1 = {4b 65 79 6c 6f 67 67 65 72 50 72 6f 63 65 73 73 } //01 00  KeyloggerProcess
		$a_01_2 = {50 61 73 73 77 6f 72 64 52 65 63 6f 76 65 72 79 } //01 00  PasswordRecovery
		$a_01_3 = {52 65 63 6f 76 65 72 42 72 6f 77 73 65 72 73 } //01 00  RecoverBrowsers
		$a_01_4 = {53 63 72 65 65 6e 73 68 6f 74 48 6f 74 4c 69 73 74 } //01 00  ScreenshotHotList
		$a_01_5 = {26 00 6b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 74 00 79 00 70 00 65 00 64 00 3d 00 } //00 00  &keystrokestyped=
		$a_00_6 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}