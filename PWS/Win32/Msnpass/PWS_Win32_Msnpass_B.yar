
rule PWS_Win32_Msnpass_B{
	meta:
		description = "PWS:Win32/Msnpass.B,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {3f 47 65 74 51 51 40 40 59 41 4b 50 41 4b 40 5a } //0a 00  ?GetQQ@@YAKPAK@Z
		$a_00_1 = {4b 65 79 62 6f 61 72 64 50 72 6f 63 } //05 00  KeyboardProc
		$a_00_2 = {69 6e 73 74 61 6c 6c 68 6f 6f 6b } //05 00  installhook
		$a_00_3 = {6d 73 6e 6d 73 67 72 } //05 00  msnmsgr
		$a_00_4 = {63 3a 5c 6d 73 6e 70 61 73 73 2e 74 78 74 } //05 00  c:\msnpass.txt
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //00 00  SetWindowsHookExA
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Msnpass_B_2{
	meta:
		description = "PWS:Win32/Msnpass.B,SIGNATURE_TYPE_PEHSTR,31 00 31 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4d 53 4e 70 77 64 72 65 67 } //0a 00  MSNpwdreg
		$a_01_1 = {73 6f 66 74 77 61 72 65 5c 6e 67 6e 73 73 73 } //0a 00  software\ngnsss
		$a_01_2 = {6d 73 6e 72 65 6f 72 64 } //05 00  msnreord
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //05 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //05 00  \shell\open\command
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //02 00  ShellExecuteA
		$a_01_6 = {6d 73 6e 6d 6f 6e 69 74 6f 72 2e 65 78 65 } //02 00  msnmonitor.exe
		$a_01_7 = {6d 73 6e 6b 65 79 68 6f 6f 6b 2e 64 6c 6c } //02 00  msnkeyhook.dll
		$a_01_8 = {6d 73 6e 6d 6f 6e 69 74 6f 72 } //02 00  msnmonitor
		$a_01_9 = {69 6e 73 74 61 6c 6c 68 6f 6f 6b } //00 00  installhook
	condition:
		any of ($a_*)
 
}