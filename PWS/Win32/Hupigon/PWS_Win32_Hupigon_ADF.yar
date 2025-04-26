
rule PWS_Win32_Hupigon_ADF{
	meta:
		description = "PWS:Win32/Hupigon.ADF,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 55 52 57 50 51 56 9c 54 68 00 00 00 00 8b 74 24 2c 89 e5 81 ec c0 00 00 00 89 } //1
		$a_01_1 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //1 Shell_NotifyIconA
		$a_00_2 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetWindowsDirectoryA
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_4 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SoftWare\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {44 45 4c 4d 45 2e 42 41 54 } //1 DELME.BAT
		$a_00_6 = {69 66 20 65 78 69 73 74 20 22 } //1 if exist "
		$a_00_7 = {67 6f 74 6f 20 74 72 79 } //1 goto try
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}