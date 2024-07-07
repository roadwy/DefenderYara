
rule PWS_Win32_OnLineGames_AX{
	meta:
		description = "PWS:Win32/OnLineGames.AX,SIGNATURE_TYPE_PEHSTR,0d 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 61 6d 65 2e 65 78 65 } //10 game.exe
		$a_01_1 = {5c 64 72 69 7e 24 7e 76 65 72 73 5c 65 7e 24 7e 74 63 5c 68 6f 73 7e 24 7e 74 73 } //1 \dri~$~vers\e~$~tc\hos~$~ts
		$a_01_2 = {25 73 7e 24 7e 25 73 7e 24 7e 2a 7e 24 7e 2e 64 6c 6c } //1 %s~$~%s~$~*~$~.dll
		$a_01_3 = {65 78 70 6c 7e 24 7e 6f 72 65 72 2e 65 78 65 } //1 expl~$~orer.exe
		$a_01_4 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 25 73 3f 25 73 } //1 http://%s:%d%s?%s
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}