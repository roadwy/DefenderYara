
rule PWS_Win32_OnLineGames_BX{
	meta:
		description = "PWS:Win32/OnLineGames.BX,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0a 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //3 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {00 72 6f 2e 64 6c 6c 00 00 57 53 50 53 74 61 72 74 75 70 } //3
		$a_02_2 = {75 73 65 72 3a [0-0b] 70 61 73 73 77 6f 72 64 3a [0-0b] 62 61 6e 6b 70 61 73 73 3a } //3
		$a_00_3 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 } //2 Proxy-Connection: 
		$a_00_4 = {6d 79 5f 67 61 6d 65 2e 62 61 74 } //2 my_game.bat
		$a_00_5 = {4d 61 70 6c 65 53 74 6f 72 79 2e 65 78 65 00 } //1
		$a_00_6 = {45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 2e 65 78 65 00 } //1
		$a_00_7 = {52 61 67 46 72 65 65 2e 65 78 65 00 } //1
		$a_00_8 = {5a 6f 64 69 61 63 4f 6e 6c 69 6e 65 2e 65 78 65 00 } //1
		$a_00_9 = {4d 61 70 6c 65 53 74 6f 72 79 20 73 65 76 65 72 } //1 MapleStory sever
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_02_2  & 1)*3+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=13
 
}
rule PWS_Win32_OnLineGames_BX_2{
	meta:
		description = "PWS:Win32/OnLineGames.BX,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 53 41 46 44 20 54 63 70 69 70 20 5b 54 43 50 2f 49 50 5d } //1 MSAFD Tcpip [TCP/IP]
		$a_01_1 = {64 65 6c 2e 62 61 74 00 ff ff ff ff 07 00 00 00 3a 5f 64 65 6c 6d 65 } //1
		$a_01_2 = {ff ff ff 8b 55 fc 8b c3 b9 12 8d 40 00 e8 6d b2 ff ff 8b c3 8b d6 e8 b0 b4 ff ff 33 c0 5a 59 59 64 89 10 68 03 8d 40 00 8d 45 fc e8 8f af ff ff c3 e9 b1 a9 ff ff eb f0 5e 5b 59 5d c3 00 00 ff ff ff ff 06 00 00 00 72 6f 2e 64 6c 6c 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}