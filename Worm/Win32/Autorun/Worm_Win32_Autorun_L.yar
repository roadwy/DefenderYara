
rule Worm_Win32_Autorun_L{
	meta:
		description = "Worm:Win32/Autorun.L,SIGNATURE_TYPE_PEHSTR,ffffffd3 00 ffffffd3 00 06 00 00 64 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //64 00  VirtualProtect
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_01_2 = {73 76 63 68 73 30 74 2e 65 78 65 } //0a 00  svchs0t.exe
		$a_01_3 = {68 74 74 70 3a 2f 2f 78 78 2e 35 32 32 6c 6f 76 65 2e 63 6e 2f 74 6f 6f 6c 2f 64 6f 77 6e } //01 00  http://xx.522love.cn/tool/down
		$a_01_4 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 48 69 64 64 65 6e 5c 53 48 4f 57 41 4c 4c 22 20 2f 76 20 43 68 65 63 6b 65 64 56 61 6c 75 65 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 30 20 2f 66 } //01 00  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" /v CheckedValue /t REG_SZ /d 0 /f
		$a_01_5 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 48 69 64 64 65 6e 5c 4e 4f 48 49 44 44 45 4e 22 20 2f 76 20 43 68 65 63 6b 65 64 56 61 6c 75 65 20 2f 74 20 52 45 47 5f 64 77 6f 72 64 20 2f 64 20 30 30 30 30 30 30 30 32 20 2f 66 } //00 00  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" /v CheckedValue /t REG_dword /d 00000002 /f
	condition:
		any of ($a_*)
 
}