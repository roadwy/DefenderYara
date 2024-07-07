
rule PWS_Win32_OnLineGames_W{
	meta:
		description = "PWS:Win32/OnLineGames.W,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b ff 8b f6 90 90 90 90 8b db 90 8b ff 90 90 8b d2 90 90 8b f6 90 8b c9 90 8b db 90 90 8b ed 8b c0 90 8b f6 8b d2 8b f6 8b ed 90 8b ff 90 8b ff 8b c0 90 8b f6 90 8b c9 8b d2 90 8b f6 90 8b d2 90 8b f6 } //5
		$a_01_1 = {8b ff 90 90 8b d2 90 90 90 8b c9 90 8b db 90 90 8b ed 8b c0 90 8b d2 8b f6 8b ed 90 8b ff 90 8b ff 8b c0 90 90 8b c9 8b d2 90 90 8b d2 } //5
		$a_02_2 = {34 46 34 46 30 30 36 34 2d 37 31 45 30 2d 34 66 30 64 2d 30 30 30 90 01 01 2d 37 30 38 34 37 36 43 37 38 31 35 46 90 00 } //2
		$a_00_3 = {33 36 30 53 61 66 65 2e 65 78 65 } //1 360Safe.exe
		$a_00_4 = {73 65 72 76 65 72 6c 69 73 74 2e 74 78 74 } //1 serverlist.txt
		$a_00_5 = {48 6f 6f 6b 2e 64 6c 6c } //1 Hook.dll
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_02_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=8
 
}