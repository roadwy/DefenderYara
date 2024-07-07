
rule PWS_Win32_OnLineGames_CPS{
	meta:
		description = "PWS:Win32/OnLineGames.CPS,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 2e 65 78 65 } //1 ElementClient.exe
		$a_00_1 = {43 75 72 72 65 6e 74 53 65 72 76 65 72 41 64 64 72 65 73 73 } //1 CurrentServerAddress
		$a_00_2 = {75 73 65 72 64 61 74 61 5c 63 75 72 72 65 6e 74 73 65 72 76 65 72 2e 69 6e 69 } //1 userdata\currentserver.ini
		$a_00_3 = {43 52 41 43 4b 49 4e 47 } //1 CRACKING
		$a_00_4 = {25 73 3f 61 63 74 69 6f 6e 3d 67 65 74 70 6f 73 26 75 3d 25 73 } //1 %s?action=getpos&u=%s
		$a_00_5 = {25 73 3f 61 63 74 69 6f 6e 3d 70 6f 73 74 6d 62 26 75 3d 25 73 26 6d 62 3d 25 73 } //1 %s?action=postmb&u=%s&mb=%s
		$a_00_6 = {3f 73 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 26 70 69 6e 3d 25 73 26 72 3d 25 73 26 6c 3d 25 73 26 6d 3d 25 73 26 6d 62 3d 25 73 } //1 ?s=%s&u=%s&p=%s&pin=%s&r=%s&l=%s&m=%s&mb=%s
		$a_01_7 = {63 6f 6e 66 69 72 6d } //1 confirm
		$a_01_8 = {6d 69 62 61 6f 2e 61 73 70 } //1 mibao.asp
		$a_01_9 = {48 4f 4f 4b 2e 64 6c 6c } //1 HOOK.dll
		$a_01_10 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}