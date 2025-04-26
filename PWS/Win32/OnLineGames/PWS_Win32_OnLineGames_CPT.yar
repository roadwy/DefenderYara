
rule PWS_Win32_OnLineGames_CPT{
	meta:
		description = "PWS:Win32/OnLineGames.CPT,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 05 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 c7 45 ?? 3a 2f 2f 77 c7 45 ?? 77 77 2e 6e c7 45 ?? 69 75 64 76 c7 45 ?? 64 2e 63 6f c7 45 ?? 6d 2f 78 69 c7 45 ?? 6e 70 6f 74 c7 45 ?? 69 61 6e 2f c7 45 ?? 6c 69 6e 2e c7 45 ?? 61 73 70 3f c7 45 ?? 61 63 3d 31 c7 45 ?? 26 61 3d 25 c7 45 ?? 73 26 73 3d } //10
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_00_3 = {73 74 72 72 63 68 72 } //1 strrchr
		$a_00_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=11
 
}