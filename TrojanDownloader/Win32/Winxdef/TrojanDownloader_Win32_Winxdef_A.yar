
rule TrojanDownloader_Win32_Winxdef_A{
	meta:
		description = "TrojanDownloader:Win32/Winxdef.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {56 57 68 98 63 40 00 6a 00 6a 00 ff 15 50 60 40 00 8b f0 ff 15 b8 60 40 00 3d b7 00 00 00 75 04 33 ff eb 06 8b c6 33 f6 8b f8 85 f6 74 07 56 ff 15 a4 60 40 00 8b c7 5f 5e c3 } //1
		$a_01_1 = {ff 15 3c 61 40 00 a3 c8 81 40 00 } //1
		$a_01_2 = {83 3d c8 81 40 00 00 75 08 6a 01 e8 0d 05 00 00 59 68 09 04 00 c0 ff 15 30 61 40 00 50 ff 15 2c 61 40 00 c9 c3 } //1
		$a_00_3 = {68 74 74 70 3a 2f 2f 73 63 61 6e 6e 65 72 2e 77 69 6e 78 64 65 66 65 6e 64 65 72 2e 63 6f 6d 2f } //1 http://scanner.winxdefender.com/
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 58 44 65 66 65 6e 64 65 72 } //1 Software\WinXDefender
		$a_00_5 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 77 69 6e 78 64 65 66 65 6e 64 65 72 2e 63 6f 6d 2f } //1 http://download.winxdefender.com/
		$a_00_6 = {25 50 52 4f 47 52 41 4d 46 49 4c 45 53 25 5c 57 69 6e 58 44 65 66 65 6e 64 65 72 5c 57 69 6e 58 44 65 66 65 6e 64 65 72 2e 65 78 65 } //1 %PROGRAMFILES%\WinXDefender\WinXDefender.exe
		$a_00_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //1 ShellExecuteW
		$a_00_8 = {55 52 4c 4f 70 65 6e 53 74 72 65 61 6d 57 } //1 URLOpenStreamW
		$a_00_9 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //1 CreateMutexW
		$a_00_10 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=11
 
}