
rule PWS_Win32_OnLineGames_ABS{
	meta:
		description = "PWS:Win32/OnLineGames.ABS,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 "
		
	strings :
		$a_01_0 = {45 6e 48 6f 6f 6b 57 69 6e 64 6f 77 } //1 EnHookWindow
		$a_01_1 = {55 6e 69 6e 73 74 61 6c 6c 48 6f 6f 6b } //1 UninstallHook
		$a_01_2 = {73 75 62 5f 67 65 74 6d 65 73 73 61 67 65 } //1 sub_getmessage
		$a_01_3 = {73 75 62 5f 6b 65 79 62 6f 61 72 64 } //1 sub_keyboard
		$a_00_4 = {67 61 6d 65 2e 65 78 65 } //1 game.exe
		$a_01_5 = {45 78 70 6c 6f 72 65 72 2e 45 58 45 } //1 Explorer.EXE
		$a_01_6 = {26 61 63 3d } //1 &ac=
		$a_01_7 = {26 6d 62 3d 6b 69 63 6b } //1 &mb=kick
		$a_01_8 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_01_9 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 20 57 69 6e 64 6f 77 } //1 ElementClient Window
		$a_01_10 = {45 6c 65 6d 65 6e 74 20 43 6c 69 65 6e 74 } //1 Element Client
		$a_01_11 = {74 69 63 6b 65 64 } //1 ticked
		$a_01_12 = {75 73 65 72 64 61 74 61 5c 63 75 72 72 65 6e 74 73 65 72 76 65 72 2e 69 6e 69 } //1 userdata\currentserver.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=10
 
}