
rule PWS_Win32_OnLineGames_IT{
	meta:
		description = "PWS:Win32/OnLineGames.IT,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //3 ReadProcessMemory
		$a_01_1 = {26 54 42 5f 43 61 72 64 50 61 73 73 77 6f 72 64 32 3d } //2 &TB_CardPassword2=
		$a_01_2 = {75 73 65 72 64 61 74 61 5c 63 75 72 72 65 6e 74 73 65 72 76 65 72 2e 69 6e 69 } //1 userdata\currentserver.ini
		$a_01_3 = {45 6c 65 6d 65 6e 74 20 43 6c 69 65 6e 74 } //1 Element Client
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
rule PWS_Win32_OnLineGames_IT_2{
	meta:
		description = "PWS:Win32/OnLineGames.IT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 64 69 6e 70 75 74 38 5f 2e 64 6c 6c } //1 \dinput8_.dll
		$a_01_1 = {b0 73 c6 44 24 39 66 52 88 44 24 3c c6 44 24 3e 63 c6 44 24 3f 5f c6 44 24 40 6f 88 44 24 41 c6 44 24 42 2e c6 44 24 43 64 c6 44 24 44 6c c6 44 24 45 6c 88 5c 24 46 ff } //1
		$a_03_2 = {c6 44 24 2c 6c c6 44 24 2d 7a c6 44 24 2e 67 c6 44 24 2f 2e 88 90 01 01 24 90 01 01 88 90 01 01 24 33 89 90 01 01 24 3c c6 44 24 18 6c c6 44 24 19 7a c6 44 24 1a 67 c6 44 24 1b 31 c6 44 24 1c 2e 88 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}