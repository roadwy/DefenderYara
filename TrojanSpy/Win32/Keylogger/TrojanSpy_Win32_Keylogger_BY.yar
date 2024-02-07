
rule TrojanSpy_Win32_Keylogger_BY{
	meta:
		description = "TrojanSpy:Win32/Keylogger.BY,SIGNATURE_TYPE_PEHSTR_EXT,79 00 79 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 00 45 00 6e 00 74 00 65 00 72 00 5d 00 } //01 00  [Enter]
		$a_01_1 = {5b 00 42 00 61 00 63 00 6b 00 53 00 70 00 61 00 63 00 65 00 5d 00 } //01 00  [BackSpace]
		$a_01_2 = {5b 00 48 00 6f 00 6d 00 65 00 5d 00 } //0a 00  [Home]
		$a_01_3 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //0a 00  GetAsyncKeyState
		$a_01_4 = {3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 } //0a 00  ===============
		$a_01_5 = {2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 } //64 00  ---------------
		$a_03_6 = {ff d3 50 68 90 01 02 40 00 ff 15 90 01 01 10 40 00 8b d0 8d 4d 90 01 01 ff d3 50 68 90 01 02 40 00 ff 15 90 01 01 10 40 00 8b d0 8d 4d 90 01 01 ff d3 90 00 } //64 00 
		$a_00_7 = {41 6d 69 6e 20 48 61 64 69 68 69 } //64 00  Amin Hadihi
		$a_01_8 = {54 63 68 65 63 6b 77 69 6e 74 78 74 } //00 00  Tcheckwintxt
	condition:
		any of ($a_*)
 
}