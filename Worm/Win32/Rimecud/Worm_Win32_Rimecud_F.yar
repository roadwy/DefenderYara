
rule Worm_Win32_Rimecud_F{
	meta:
		description = "Worm:Win32/Rimecud.F,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 20 61 6e 20 49 6e 73 74 61 6e 74 20 4d 65 73 73 61 67 65 } //1 Send an Instant Message
		$a_00_1 = {59 49 4d 49 6e 70 75 74 57 69 6e 64 6f 77 } //1 YIMInputWindow
		$a_00_2 = {41 70 70 20 50 61 74 68 73 5c 49 43 51 2e 65 78 65 } //1 App Paths\ICQ.exe
		$a_00_3 = {69 63 6f 6e 3d 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 53 59 53 54 45 4d 33 32 5c 53 48 45 4c 4c 33 32 2e 44 6c 6c } //1 icon=%systemroot%\SYSTEM32\SHELL32.Dll
		$a_00_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 3d 76 73 68 6f 73 74 2e 65 78 65 } //1 ShellExecute=vshost.exe
		$a_00_5 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_02_6 = {5b 49 43 51 20 4d 65 73 73 61 67 65 20 55 73 65 72 5d 90 01 01 55 49 4e 3d 25 73 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1) >=7
 
}