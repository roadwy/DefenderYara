
rule PWS_Win32_OnLineGames_CPD{
	meta:
		description = "PWS:Win32/OnLineGames.CPD,SIGNATURE_TYPE_PEHSTR_EXT,35 00 35 00 0b 00 00 "
		
	strings :
		$a_02_0 = {63 3a 5c 66 66 31 ?? 2e 74 78 74 } //10
		$a_01_1 = {53 74 61 72 74 48 6f 6f 6b } //10 StartHook
		$a_00_2 = {53 74 6f 70 48 6f 6f 6b } //10 StopHook
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_01_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //10 SetWindowsHookExA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_00_6 = {3f 70 61 73 73 6d 65 6d 3d } //1 ?passmem=
		$a_00_7 = {26 62 69 6e 66 69 6c 65 3d } //1 &binfile=
		$a_00_8 = {26 62 69 6e 64 61 74 61 3d } //1 &bindata=
		$a_00_9 = {46 3a 5c 77 6f 72 6b 5c 66 66 31 31 } //1 F:\work\ff11
		$a_00_10 = {5c 69 75 6f 69 75 6f 5c 73 79 73 75 74 69 6c 73 2e 70 61 73 } //1 \iuoiuo\sysutils.pas
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=53
 
}