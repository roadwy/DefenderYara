
rule PWS_Win32_OnLineGames_MM{
	meta:
		description = "PWS:Win32/OnLineGames.MM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 73 6f 63 6b 68 65 6c 70 33 32 2e 65 78 65 } //1 %s\sockhelp32.exe
		$a_01_1 = {25 73 5c 73 63 61 6e 73 6f 63 6b 2e 65 78 65 } //1 %s\scansock.exe
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 64 2e 25 64 2e 25 64 2e 25 64 3a 38 30 38 2f 47 65 74 4d 65 49 6e 66 6f 2e 61 73 70 78 } //1 http://%d.%d.%d.%d:808/GetMeInfo.aspx
		$a_01_3 = {25 73 3f 69 64 3d 25 73 26 70 61 73 73 3d 25 73 26 70 6c 61 63 65 3d 25 73 26 6c 65 76 65 6c 3d 25 64 26 6d 6f 6e 65 79 3d 25 64 26 71 31 3d 25 73 26 71 32 3d 25 73 26 71 33 3d 25 73 26 61 31 3d 25 73 26 61 32 3d 25 73 26 61 33 3d 25 73 26 73 6a 3d 25 73 26 76 65 72 3d 25 73 26 73 69 67 6e 3d 25 73 } //1 %s?id=%s&pass=%s&place=%s&level=%d&money=%d&q1=%s&q2=%s&q3=%s&a1=%s&a2=%s&a3=%s&sj=%s&ver=%s&sign=%s
		$a_01_4 = {64 6e 66 68 61 63 6b 2e 63 79 } //1 dnfhack.cy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}