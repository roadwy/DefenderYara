
rule TrojanDownloader_Win32_Renos_BAG{
	meta:
		description = "TrojanDownloader:Win32/Renos.BAG,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 12 00 00 0a 00 "
		
	strings :
		$a_00_0 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 69 6e 66 65 63 74 65 64 21 20 49 74 20 69 73 20 72 65 63 6f 6d 6d 65 6e 64 65 64 20 74 6f 20 73 74 61 72 74 20 73 70 79 77 61 72 65 20 63 6c 65 61 6e 65 72 20 74 6f 6f 6c 2e } //0a 00  Your computer is infected! It is recommended to start spyware cleaner tool.
		$a_00_1 = {57 61 72 6e 69 6e 67 21 20 53 65 63 75 72 69 74 79 20 72 65 70 6f 72 74 } //0a 00  Warning! Security report
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //0a 00  CreateToolhelp32Snapshot
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 63 74 69 76 65 44 65 73 6b 74 6f 70 } //01 00  Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop
		$a_00_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //01 00  Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
		$a_00_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } //01 00  Software\Microsoft\Windows\CurrentVersion\Policies\System
		$a_00_9 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 73 6c 64 72 2e 63 6f 6d 2f 69 6e 64 65 78 35 2e 70 68 70 3f 61 64 76 3d 31 34 31 } //01 00  http://downloadfilesldr.com/index5.php?adv=141
		$a_00_10 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 73 6c 64 72 2e 63 6f 6d 2f 69 6e 64 65 78 34 2e 70 68 70 3f 61 64 76 3d 31 34 31 } //01 00  http://downloadfilesldr.com/index4.php?adv=141
		$a_00_11 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 73 6c 64 72 2e 63 6f 6d 2f 69 6e 64 65 78 33 2e 70 68 70 3f 61 64 76 3d 31 34 31 } //01 00  http://downloadfilesldr.com/index3.php?adv=141
		$a_00_12 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 73 6c 64 72 2e 63 6f 6d 2f 69 6e 64 65 78 32 2e 70 68 70 3f 61 64 76 3d 31 34 31 } //01 00  http://downloadfilesldr.com/index2.php?adv=141
		$a_00_13 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 73 6c 64 72 2e 63 6f 6d 2f 61 6c 6c 66 69 6c 65 2e 6a 70 67 } //01 00  http://downloadfilesldr.com/allfile.jpg
		$a_00_14 = {68 74 74 70 3a 2f 2f 73 70 79 77 61 72 65 73 6f 66 74 73 74 6f 70 2e 63 6f 6d 2f 6c 6f 61 64 2e 70 68 70 3f 61 64 76 3d 31 34 31 } //01 00  http://spywaresoftstop.com/load.php?adv=141
		$a_00_15 = {68 74 74 70 3a 2f 2f 73 70 79 77 61 72 65 73 6f 66 74 73 74 6f 70 2e 63 6f 6d 2f 77 66 64 66 64 67 68 66 64 67 68 6a 2e 68 74 6d } //01 00  http://spywaresoftstop.com/wfdfdghfdghj.htm
		$a_00_16 = {68 74 74 70 3a 2f 2f 73 70 79 77 61 72 65 73 6f 66 74 73 74 6f 70 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 31 34 31 2f 73 65 74 75 70 2e 65 78 65 } //01 00  http://spywaresoftstop.com/download/141/setup.exe
		$a_00_17 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 70 79 77 61 72 65 53 6f 66 74 53 74 6f 70 5c 53 70 79 77 61 72 65 53 6f 66 74 53 74 6f 70 2e 65 78 65 } //00 00  C:\Program Files\SpywareSoftStop\SpywareSoftStop.exe
	condition:
		any of ($a_*)
 
}