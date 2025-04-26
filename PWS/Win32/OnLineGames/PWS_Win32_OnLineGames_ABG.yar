
rule PWS_Win32_OnLineGames_ABG{
	meta:
		description = "PWS:Win32/OnLineGames.ABG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {25 73 3f 61 63 74 69 6f 6e 3d 26 4e 61 6d 65 3d 25 73 26 53 74 61 74 65 3d 25 64 } //1 %s?action=&Name=%s&State=%d
		$a_00_1 = {3f 67 61 6d 65 54 79 70 65 } //1 ?gameType
		$a_00_2 = {26 4e 61 6d 65 3d 25 73 26 70 61 73 73 77 6f 72 64 3d 25 73 } //1 &Name=%s&password=%s
		$a_00_3 = {67 61 6d 65 2e 65 78 65 } //1 game.exe
		$a_00_4 = {73 6f 75 6e 64 2e 64 6c 6c } //1 sound.dll
		$a_00_5 = {25 73 28 25 64 29 20 } //1 %s(%d) 
		$a_00_6 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 } //1 regsvr32.exe /s 
		$a_01_7 = {26 53 65 72 76 65 72 3d 25 73 } //1 &Server=%s
		$a_01_8 = {26 5a 6f 6e 65 3d 25 73 } //1 &Zone=%s
		$a_01_9 = {26 6e 69 63 6b 4e 61 6d 65 3d 25 73 26 6c 6f 72 64 3d 25 73 26 4c 65 76 65 6c 3d 25 73 26 4d 6f 6e 65 79 3d 25 75 26 67 6f 6c 64 43 6f 69 6e 3d 25 75 26 59 42 3d 25 75 26 } //1 &nickName=%s&lord=%s&Level=%s&Money=%u&goldCoin=%u&YB=%u&
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}