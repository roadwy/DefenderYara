
rule TrojanDownloader_Win32_Delf{
	meta:
		description = "TrojanDownloader:Win32/Delf,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //10 FPUMaskValue
		$a_00_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_00_3 = {57 69 6e 45 78 65 63 } //10 WinExec
		$a_01_4 = {43 3a 5c 64 77 6e 53 65 74 75 70 5c } //5 C:\dwnSetup\
		$a_01_5 = {77 78 70 53 65 74 75 70 } //5 wxpSetup
		$a_01_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 61 64 73 2e 63 6e 2f 73 65 74 75 70 2f 73 65 74 75 70 2e 61 73 70 3f 69 64 3d 25 73 26 70 63 69 64 3d 25 73 } //1 http://www.goads.cn/setup/setup.asp?id=%s&pcid=%s
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 6f 66 74 75 75 2e 63 6e 2f 73 65 74 75 70 2f 73 65 74 75 70 2e 61 73 70 3f 69 64 3d 25 73 26 70 63 69 64 3d 25 73 } //1 http://www.softuu.cn/setup/setup.asp?id=%s&pcid=%s
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=51
 
}
rule TrojanDownloader_Win32_Delf_2{
	meta:
		description = "TrojanDownloader:Win32/Delf,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {ba cc 03 45 00 e8 90 01 03 ff b8 20 ea 45 00 ba 00 04 45 00 90 00 } //1
		$a_03_1 = {ba 18 04 45 00 e8 90 01 03 ff b8 20 ea 45 00 ba 54 04 45 00 90 00 } //1
		$a_00_2 = {76 69 64 73 78 78 78 76 69 64 73 2e 63 6f 6d } //1 vidsxxxvids.com
		$a_00_3 = {73 65 6c 6c 62 75 79 74 72 61 66 66 2e 63 6f 6d } //1 sellbuytraff.com
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Delf_3{
	meta:
		description = "TrojanDownloader:Win32/Delf,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 8b d8 b8 a4 35 45 00 e8 5b 53 fb ff 84 c0 74 0e a1 c0 4e 45 00 8b 00 e8 e7 c7 ff ff 5b c3 } //1
		$a_00_1 = {77 69 6e 75 70 2e 6a 70 67 } //1 winup.jpg
		$a_00_2 = {4f 75 74 6c 6f 6f 6b 73 2e 6a 70 67 } //1 Outlooks.jpg
		$a_02_3 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 4d 53 4e 20 4d 65 73 73 65 6e 67 65 72 5c 44 65 76 69 63 65 20 4d 61 6e 61 67 65 72 5c 6d 73 6e 67 72 5c 90 02 08 2e 65 78 65 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Delf_4{
	meta:
		description = "TrojanDownloader:Win32/Delf,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {69 6e 64 65 78 2e 61 73 70 90 01 0b 69 6e 64 65 78 2e 68 74 6d 90 01 0b 69 6e 64 65 78 2e 68 74 6d 6c 90 01 0a 69 6e 64 65 78 2e 70 68 70 90 01 0b 44 65 66 61 75 6c 74 2e 61 73 70 90 01 09 44 65 66 61 75 6c 74 2e 68 74 6d 90 01 09 44 65 66 61 75 6c 74 2e 68 74 6d 6c 90 01 0c 44 65 66 61 75 6c 74 2e 50 48 50 90 00 } //1
		$a_00_1 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 57 33 53 56 43 5c 50 61 72 61 6d 65 74 65 72 73 5c 56 69 72 74 75 61 6c 20 52 6f 6f 74 73 } //1 SYSTEM\ControlSet001\Services\W3SVC\Parameters\Virtual Roots
		$a_02_2 = {6d 79 64 6f 77 6e 90 01 0a 68 74 74 70 3a 2f 2f 90 01 31 26 74 67 69 64 3d 90 01 0a 26 61 64 64 72 65 73 73 3d 90 00 } //1
		$a_00_3 = {7a 73 6d 73 64 66 33 32 2e 69 6e 69 } //1 zsmsdf32.ini
		$a_00_4 = {7a 68 71 62 64 66 31 36 2e 69 6e 69 } //1 zhqbdf16.ini
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanDownloader_Win32_Delf_5{
	meta:
		description = "TrojanDownloader:Win32/Delf,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 00 00 00 43 00 00 00 68 74 74 70 3a 2f 2f 63 61 72 6e 61 76 61 6c 32 30 30 38 66 6f 74 6f 73 2e 63 6f 6d 2e 64 69 73 68 35 30 33 31 2e 6e 65 74 2e 69 62 69 7a 64 6e 73 2e 63 6f 6d 2f 53 4f 55 52 43 45 5f 48 34 43 4b 33 52 00 dc 03 81 00 dc 03 81 00 80 01 00 00 65 00 00 00 ec 03 81 00 ec 03 81 00 10 00 00 00 20 00 00 00 1b 00 00 00 00 00 00 00 09 00 00 00 77 69 6e 64 73 2e 65 78 38 00 00 00 2f 00 00 00 00 00 00 00 1d 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 77 69 6e 64 73 2e 65 78 65 00 2f 8b } //10
		$a_00_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 72 75 6e 64 6c 6c 6c 2e 65 78 65 } //5 C:\WINDOWS\SYSTEM32\rundlll.exe
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 44 } //5 Software\Microsoft\Windows\CurrentVersion\RuD
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5) >=10
 
}
rule TrojanDownloader_Win32_Delf_6{
	meta:
		description = "TrojanDownloader:Win32/Delf,SIGNATURE_TYPE_PEHSTR_EXT,ffffff94 0c 26 0c 09 00 00 "
		
	strings :
		$a_01_0 = {54 57 69 6e 64 6f 77 43 6c 61 73 73 54 55 70 64 61 74 65 72 41 70 70 6c 69 63 61 74 69 6f 6e } //1000 TWindowClassTUpdaterApplication
		$a_02_1 = {68 74 74 70 3a 2f 2f 38 30 2e 36 39 2e 31 36 30 2e 90 05 03 0a 30 2d 39 2f 75 70 64 61 74 65 2f 90 00 } //1000
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1000 SOFTWARE\Borland\Delphi\RTL
		$a_00_3 = {32 42 42 44 37 43 31 34 2d 46 30 41 38 2d 32 33 43 32 2d 39 30 30 39 2d 30 46 30 45 45 33 37 32 36 41 42 34 } //5 2BBD7C14-F0A8-23C2-9009-0F0EE3726AB4
		$a_00_4 = {33 30 39 35 38 31 31 38 2d 34 36 34 35 2d 34 30 36 34 2d 38 35 42 31 2d 42 35 33 44 37 36 33 31 33 36 37 32 } //5 30958118-4645-4064-85B1-B53D76313672
		$a_00_5 = {73 61 66 65 2d 75 70 64 61 74 65 73 2e 74 78 74 } //5 safe-updates.txt
		$a_01_6 = {26 72 65 71 75 65 73 74 3d 6c 69 73 74 26 74 79 70 65 3d } //5 &request=list&type=
		$a_00_7 = {48 50 20 55 70 64 61 74 65 20 41 73 73 69 73 74 61 6e 74 } //100 HP Update Assistant
		$a_00_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //100 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1000+(#a_02_1  & 1)*1000+(#a_00_2  & 1)*1000+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5+(#a_00_5  & 1)*5+(#a_01_6  & 1)*5+(#a_00_7  & 1)*100+(#a_00_8  & 1)*100) >=3110
 
}
rule TrojanDownloader_Win32_Delf_7{
	meta:
		description = "TrojanDownloader:Win32/Delf,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //1 Software\Borland\Delphi\Locales
		$a_01_1 = {64 65 6c 61 6c 6c 6d 6f 6e 69 74 6f 72 66 69 6c 65 2e 65 78 65 } //1 delallmonitorfile.exe
		$a_01_2 = {4e 74 68 6f 73 74 2e 65 78 65 } //1 Nthost.exe
		$a_01_3 = {32 32 32 2e 31 32 32 2e 31 36 33 2e 39 2f 69 6e 73 74 61 6c 6c 5f 63 6f 75 6e 74 2e 68 74 6d 6c 3f 69 64 3d 4e 74 68 6f 73 74 26 4d 41 43 3d } //1 222.122.163.9/install_count.html?id=Nthost&MAC=
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_01_6 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_7 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}