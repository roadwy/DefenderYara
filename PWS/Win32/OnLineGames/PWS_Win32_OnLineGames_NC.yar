
rule PWS_Win32_OnLineGames_NC{
	meta:
		description = "PWS:Win32/OnLineGames.NC,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 66 6a 6c 6f 67 69 6e 2e 65 78 65 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\fjlogin.exe
		$a_00_1 = {6c 61 73 74 47 61 6d 65 53 65 72 76 65 72 } //1 lastGameServer
		$a_00_2 = {6c 61 73 74 5a 6f 6e 65 } //1 lastZone
		$a_01_3 = {2f 5f 46 4a 4c 6f 67 69 6e 2e 62 69 6e } //1 /_FJLogin.bin
		$a_00_4 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 2e 65 78 65 } //1 ElementClient.exe
		$a_00_5 = {47 74 53 61 6c 6f 6f 6e 2e 65 78 65 } //1 GtSaloon.exe
		$a_00_6 = {77 6f 77 2e 65 78 65 } //1 wow.exe
		$a_00_7 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 20 57 69 6e 64 6f 77 } //1 ElementClient Window
		$a_00_8 = {25 73 3f 61 3d 25 73 26 73 3d 25 73 26 75 3d 25 73 26 61 63 3d 74 } //1 %s?a=%s&s=%s&u=%s&ac=t
		$a_00_9 = {72 73 61 65 6e 68 2e 64 72 73 61 65 6e 68 2e 64 6c 6c } //1 rsaenh.drsaenh.dll
		$a_00_10 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 34 00 30 00 39 00 37 00 } //1 explore.exe4097
		$a_00_11 = {78 00 75 00 6c 00 2e 00 64 00 6c 00 6c 00 } //1 xul.dll
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=12
 
}