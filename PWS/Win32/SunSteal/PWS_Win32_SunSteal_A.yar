
rule PWS_Win32_SunSteal_A{
	meta:
		description = "PWS:Win32/SunSteal.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_00_0 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //1 GetWindowThreadProcessId
		$a_01_1 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_2 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetWindowsDirectoryA
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_4 = {53 75 6e 67 61 6d 65 2e 65 78 65 } //4 Sungame.exe
		$a_00_5 = {2f 6c 69 6e 2e 61 73 70 } //3 /lin.asp
		$a_01_6 = {25 73 3f 72 6c 3d 25 64 26 73 3d 25 64 26 75 3d 25 73 26 70 3d 25 73 26 73 70 3d 25 73 26 72 3d 25 73 26 6c 3d 25 64 26 6d 6c 3d 25 64 26 6d 68 3d 25 64 } //3 %s?rl=%d&s=%d&u=%s&p=%s&sp=%s&r=%s&l=%d&ml=%d&mh=%d
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*4+(#a_00_5  & 1)*3+(#a_01_6  & 1)*3) >=12
 
}