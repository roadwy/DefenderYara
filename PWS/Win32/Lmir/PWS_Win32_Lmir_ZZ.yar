
rule PWS_Win32_Lmir_ZZ{
	meta:
		description = "PWS:Win32/Lmir.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0d 00 00 05 00 "
		
	strings :
		$a_00_0 = {5a 74 47 61 6d 65 5f 49 4e } //05 00  ZtGame_IN
		$a_00_1 = {5a 74 47 61 6d 65 5f 4f 55 54 } //01 00  ZtGame_OUT
		$a_00_2 = {6f 74 68 65 72 3d } //01 00  other=
		$a_00_3 = {65 71 75 3d } //01 00  equ=
		$a_00_4 = {72 6f 6c 65 3d } //01 00  role=
		$a_00_5 = {77 75 70 69 6e 3d } //01 00  wupin=
		$a_00_6 = {70 69 6e 3d } //01 00  pin=
		$a_00_7 = {70 61 73 73 3d } //01 00  pass=
		$a_00_8 = {67 61 6d 65 69 64 3d } //01 00  gameid=
		$a_00_9 = {73 65 72 76 65 72 3d } //01 00  server=
		$a_00_10 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_01_11 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_00_12 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //00 00  UnhookWindowsHookEx
	condition:
		any of ($a_*)
 
}