
rule TrojanClicker_Win32_Small_JD{
	meta:
		description = "TrojanClicker:Win32/Small.JD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 70 72 6f 74 65 63 74 65 64 5c 41 56 50 37 5c 70 72 6f 66 69 6c 65 73 5c 41 56 53 65 72 76 69 63 65 5c 73 65 74 74 69 6e 67 73 5c 45 78 63 6c 75 64 65 73 5c 30 30 30 30 5c 56 65 72 64 69 63 74 50 61 74 68 } //01 00  SOFTWARE\KasperskyLab\protected\AVP7\profiles\AVService\settings\Excludes\0000\VerdictPath
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 70 72 6f 74 65 63 74 65 64 5c 41 56 50 37 5c 70 72 6f 66 69 6c 65 73 5c 41 56 53 65 72 76 69 63 65 5c 73 65 74 74 69 6e 67 73 5c 45 78 63 6c 75 64 65 73 5c 30 30 30 30 5c 54 61 73 6b 4c 69 73 74 } //01 00  SOFTWARE\KasperskyLab\protected\AVP7\profiles\AVService\settings\Excludes\0000\TaskList
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 70 72 6f 74 65 63 74 65 64 5c 41 56 50 37 5c 70 72 6f 66 69 6c 65 73 5c 41 56 53 65 72 76 69 63 65 5c 73 65 74 74 69 6e 67 73 5c 45 78 63 6c 75 64 65 73 5c 30 30 30 30 5c 4f 62 6a 65 63 74 } //01 00  SOFTWARE\KasperskyLab\protected\AVP7\profiles\AVService\settings\Excludes\0000\Object
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_01_6 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00  \drivers\etc\hosts
		$a_01_7 = {5c 5c 2e 5c 52 45 53 53 44 54 44 4f 53 } //01 00  \\.\RESSDTDOS
		$a_01_8 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6e 2f 73 65 61 72 63 68 3f 63 6f 6d 70 6c 65 74 65 3d 31 26 68 6c 3d 7a 68 2d 43 4e 26 69 6e 6c 61 6e 67 3d 7a 68 2d 43 4e 26 6e 65 77 77 69 6e 64 6f 77 3d 31 26 71 3d } //01 00  http://www.google.cn/search?complete=1&hl=zh-CN&inlang=zh-CN&newwindow=1&q=
		$a_01_9 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //00 00  DisableRegistryTools
	condition:
		any of ($a_*)
 
}