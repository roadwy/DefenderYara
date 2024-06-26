
rule PWS_Win32_OnLineGames_ABS{
	meta:
		description = "PWS:Win32/OnLineGames.ABS,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 48 6f 6f 6b 57 69 6e 64 6f 77 } //01 00  EnHookWindow
		$a_01_1 = {55 6e 69 6e 73 74 61 6c 6c 48 6f 6f 6b } //01 00  UninstallHook
		$a_01_2 = {73 75 62 5f 67 65 74 6d 65 73 73 61 67 65 } //01 00  sub_getmessage
		$a_01_3 = {73 75 62 5f 6b 65 79 62 6f 61 72 64 } //01 00  sub_keyboard
		$a_00_4 = {67 61 6d 65 2e 65 78 65 } //01 00  game.exe
		$a_01_5 = {45 78 70 6c 6f 72 65 72 2e 45 58 45 } //01 00  Explorer.EXE
		$a_01_6 = {26 61 63 3d } //01 00  &ac=
		$a_01_7 = {26 6d 62 3d 6b 69 63 6b } //01 00  &mb=kick
		$a_01_8 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_01_9 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 20 57 69 6e 64 6f 77 } //01 00  ElementClient Window
		$a_01_10 = {45 6c 65 6d 65 6e 74 20 43 6c 69 65 6e 74 } //01 00  Element Client
		$a_01_11 = {74 69 63 6b 65 64 } //01 00  ticked
		$a_01_12 = {75 73 65 72 64 61 74 61 5c 63 75 72 72 65 6e 74 73 65 72 76 65 72 2e 69 6e 69 } //00 00  userdata\currentserver.ini
	condition:
		any of ($a_*)
 
}