
rule TrojanDropper_Win32_Warece_B{
	meta:
		description = "TrojanDropper:Win32/Warece.B,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 0c 00 00 "
		
	strings :
		$a_00_0 = {5c 6e 76 73 76 63 31 30 32 34 2e 64 6c 6c } //1 \nvsvc1024.dll
		$a_00_1 = {64 65 6c 20 43 3a 5c 6d 79 61 70 70 2e 65 78 65 } //1 del C:\myapp.exe
		$a_00_2 = {69 66 20 65 78 69 73 74 20 43 3a 5c 6d 79 61 70 70 2e 65 78 65 20 67 6f 74 6f 20 74 72 79 } //1 if exist C:\myapp.exe goto try
		$a_00_3 = {5c 70 72 69 6e 74 65 72 2e 65 78 65 } //1 \printer.exe
		$a_00_4 = {73 70 6f 6f 6c 76 73 68 65 6c 6c } //1 spoolvshell
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 Software\Microsoft\Windows NT\CurrentVersion
		$a_00_6 = {77 6f 77 66 78 2e 64 6c 6c } //1 wowfx.dll
		$a_00_7 = {5f 74 72 61 79 45 76 65 6e 74 } //1 _trayEvent
		$a_00_8 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //1 ShellExecuteExA
		$a_00_9 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_10 = {5c 00 6e 00 76 00 73 00 76 00 63 00 31 00 30 00 32 00 34 00 2e 00 64 00 6c 00 6c 00 } //1 \nvsvc1024.dll
		$a_02_11 = {8d 85 ec fc ff ff 6a 1a 50 56 ff 15 90 01 02 40 00 8d 85 ec fc ff ff 50 8d 85 f4 fe ff ff 50 e8 90 01 02 00 00 8d 85 f4 fe ff ff 68 90 01 02 40 00 50 e8 90 01 02 00 00 8d 85 ec fc ff ff 50 8d 85 f0 fd ff ff 50 e8 90 01 02 00 00 8d 85 f0 fd ff ff 68 90 01 02 40 00 50 e8 90 01 02 00 00 68 90 01 02 40 00 e8 90 01 02 ff ff 83 c4 24 33 c0 bb 00 26 00 00 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_02_11  & 1)*10) >=20
 
}