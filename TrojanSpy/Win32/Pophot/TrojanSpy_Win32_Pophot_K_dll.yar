
rule TrojanSpy_Win32_Pophot_K_dll{
	meta:
		description = "TrojanSpy:Win32/Pophot.K!dll,SIGNATURE_TYPE_PEHSTR,22 00 22 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 6f 00 00 ff ff ff ff 04 00 00 00 6b 69 6c 6c 00 00 00 00 ff ff ff ff 04 00 00 00 6d 73 67 73 00 00 00 00 ff ff ff ff 03 00 00 00 73 79 73 } //10
		$a_01_1 = {72 75 6e 00 ff ff ff ff 03 00 00 00 6d 73 67 00 ff ff ff ff 03 00 00 00 76 65 72 00 ff ff ff ff 06 00 00 00 6d 79 64 6f 77 6e } //10
		$a_01_2 = {64 66 7a 68 71 62 2e 65 78 65 } //10 dfzhqb.exe
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run
		$a_01_5 = {53 74 61 72 74 75 70 } //1 Startup
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=34
 
}