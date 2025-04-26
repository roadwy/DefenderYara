
rule PWS_Win32_OnLineGames_JK{
	meta:
		description = "PWS:Win32/OnLineGames.JK,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 61 63 74 69 6f 6e 3d 70 6f 73 74 6d 62 26 75 3d 25 73 26 6d 62 3d 25 73 } //1 %s?action=postmb&u=%s&mb=%s
		$a_01_1 = {25 73 3f 61 63 74 69 6f 6e 3d 74 65 73 74 6c 6f 63 6b 32 26 75 3d 25 73 } //1 %s?action=testlock2&u=%s
		$a_01_2 = {51 51 4c 6f 67 69 6e 2e 65 78 65 } //1 QQLogin.exe
		$a_01_3 = {4c 6f 61 64 44 6c 6c } //1 LoadDll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}