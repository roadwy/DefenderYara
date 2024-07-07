
rule PWS_Win32_Frethog_gen_G{
	meta:
		description = "PWS:Win32/Frethog.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_00_1 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_00_2 = {52 61 76 4d 6f 6e } //3 RavMon
		$a_00_3 = {41 6c 65 72 74 44 69 61 6c 6f 67 20 } //3 AlertDialog 
		$a_00_4 = {63 6f 6e 66 69 67 2e 77 74 66 } //8 config.wtf
		$a_00_5 = {72 65 61 6c 6d 4c 69 73 74 } //8 realmList
		$a_01_6 = {53 65 63 75 72 69 74 79 4d 61 74 72 69 78 46 72 61 6d 65 } //30 SecurityMatrixFrame
		$a_00_7 = {25 73 3f 61 3d 25 73 26 73 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 26 70 69 6e 3d 25 73 26 72 3d 25 73 26 6c 3d 25 64 26 6d 3d 25 64 } //30 %s?a=%s&s=%s&u=%s&p=%s&pin=%s&r=%s&l=%d&m=%d
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*8+(#a_00_5  & 1)*8+(#a_01_6  & 1)*30+(#a_00_7  & 1)*30) >=42
 
}
rule PWS_Win32_Frethog_gen_G_2{
	meta:
		description = "PWS:Win32/Frethog.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,ffffff84 00 ffffff83 00 09 00 00 "
		
	strings :
		$a_00_0 = {5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 5c 65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 2e 65 78 65 } //100
		$a_00_1 = {68 74 74 70 3a 2f 2f 61 73 70 78 2e 76 6f 64 33 38 2e 63 6f 6d 2f } //10 http://aspx.vod38.com/
		$a_00_2 = {68 74 74 70 3a 2f 2f 61 73 70 78 2e 71 71 75 73 2e 6e 65 74 2f 77 61 6e 6d 65 69 2f 6c 6f 67 69 6e 2e 61 73 70 } //10 http://aspx.qqus.net/wanmei/login.asp
		$a_02_3 = {7b 41 45 42 36 37 31 37 45 2d 37 45 31 39 2d 31 31 64 30 2d 39 37 45 45 2d 30 30 43 30 34 46 44 39 31 39 37 90 01 01 7d 90 00 } //10
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_00_5 = {74 70 52 65 71 75 65 73 74 } //1 tpRequest
		$a_00_6 = {25 73 73 65 74 63 6f 64 76 61 6c 75 65 2e 61 73 70 3f 75 73 65 72 6e 61 6d 65 3d 25 73 26 63 3d 25 73 25 73 25 73 } //1 %ssetcodvalue.asp?username=%s&c=%s%s%s
		$a_00_7 = {25 73 73 65 74 73 74 61 74 75 73 2e 61 73 70 3f 75 73 65 72 6e 61 6d 65 3d 25 73 26 73 3d } //1 %ssetstatus.asp?username=%s&s=
		$a_00_8 = {25 73 3f 75 3d 25 73 26 70 3d 25 73 26 63 70 3d 25 73 26 73 3d 25 73 26 6e 3d 25 73 26 6c 3d 25 64 26 76 3d 25 73 } //1 %s?u=%s&p=%s&cp=%s&s=%s&n=%s&l=%d&v=%s
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=131
 
}