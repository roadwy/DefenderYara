
rule TrojanDownloader_Win32_Satray_B{
	meta:
		description = "TrojanDownloader:Win32/Satray.B,SIGNATURE_TYPE_PEHSTR_EXT,71 00 71 00 0e 00 00 "
		
	strings :
		$a_00_0 = {5c 76 65 72 63 6c 73 69 64 2e 65 78 65 } //1 \verclsid.exe
		$a_00_1 = {49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //1 InProcServer32
		$a_00_2 = {43 4c 53 49 44 5c 7b 41 43 41 44 41 42 41 46 2d 31 30 30 30 2d 30 30 31 30 2d 38 30 30 30 2d 31 30 41 41 30 30 36 44 32 45 41 34 7d } //1 CLSID\{ACADABAF-1000-0010-8000-10AA006D2EA4}
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_00_4 = {45 6e 61 62 6c 65 46 69 72 65 77 61 6c 6c } //1 EnableFirewall
		$a_00_5 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 } //1 SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile
		$a_00_6 = {5c 64 72 69 76 65 72 73 } //1 \drivers
		$a_00_7 = {68 74 74 70 3a 2f 2f 6f 31 61 2e 63 6e 2f 43 6f 75 6e 74 65 72 2f 4e 65 77 43 6f 75 6e 74 65 72 2e 61 73 70 3f 50 61 72 61 6d 3d } //1 http://o1a.cn/Counter/NewCounter.asp?Param=
		$a_00_8 = {4d 79 20 42 65 61 75 74 69 66 75 6c 20 67 69 72 6c 21 21 21 } //1 My Beautiful girl!!!
		$a_00_9 = {64 3a 5c 4d 79 44 6f 63 75 6d 65 6e 74 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 50 72 6f 6a 65 63 74 73 5c 44 6f 77 6e 6c 6f 61 64 65 72 20 20 50 72 6f 6a 65 63 74 20 59 55 5c 44 6f 77 6e 6c 6f 61 64 65 72 4d 61 69 6e 5c 44 6f 77 6e 6c 6f 61 64 65 72 44 6c 6c 2e 70 64 62 } //1 d:\MyDocument\Visual Studio Projects\Downloader  Project YU\DownloaderMain\DownloaderDll.pdb
		$a_00_10 = {69 70 63 6f 6e 66 69 67 20 2f 61 6c 6c } //1 ipconfig /all
		$a_00_11 = {68 74 74 70 3a 2f 2f 6f 31 61 2e 63 6e 2f 73 6f 73 6f 2f 6d 69 2f 6c 6f 67 6f 2e 67 69 66 } //1 http://o1a.cn/soso/mi/logo.gif
		$a_00_12 = {50 68 79 73 69 63 61 6c 20 41 64 64 72 65 73 73 2e 20 2e 20 2e 20 2e 20 2e 20 2e 20 2e 20 2e 20 2e 20 3a } //1 Physical Address. . . . . . . . . :
		$a_02_13 = {81 ec 0c 01 00 00 a1 a0 b0 00 10 53 56 57 89 84 24 14 01 00 00 8d 44 24 0c 50 68 3f 00 0f 00 6a 00 68 08 92 00 10 68 02 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 8b 1d ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 75 1b 8b 4c 24 0c 6a 00 6a 00 6a 01 6a 00 68 e0 91 00 10 51 ff d3 } //100
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_02_13  & 1)*100) >=113
 
}