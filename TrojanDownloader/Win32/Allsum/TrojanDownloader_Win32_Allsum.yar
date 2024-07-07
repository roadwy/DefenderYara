
rule TrojanDownloader_Win32_Allsum{
	meta:
		description = "TrojanDownloader:Win32/Allsum,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 64 6c 6c 00 51 75 65 72 79 50 6c 75 67 69 6e 00 00 00 } //10
		$a_00_1 = {64 3a 5c 77 6f 72 6b 5c 63 66 73 32 2e 6d 65 5c 63 66 73 32 5c 73 72 63 5c 6d 61 69 6e 5c } //1 d:\work\cfs2.me\cfs2\src\main\
		$a_00_2 = {65 76 65 6e 74 61 64 63 6c 69 63 6b } //1 eventadclick
		$a_00_3 = {68 74 74 70 3a 2f 2f 00 32 30 32 2e 31 30 34 2e 31 31 2e 39 34 } //1
		$a_01_4 = {53 48 4f 57 20 41 44 20 50 6c 75 67 69 6e } //1 SHOW AD Plugin
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}
rule TrojanDownloader_Win32_Allsum_2{
	meta:
		description = "TrojanDownloader:Win32/Allsum,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //10 Microsoft Visual C++ Runtime Library
		$a_00_1 = {38 41 34 32 38 30 41 44 2d 39 42 33 37 2d 34 39 32 32 2d 41 35 31 44 2d 37 33 46 33 43 33 41 33 32 41 46 37 } //1 8A4280AD-9B37-4922-A51D-73F3C3A32AF7
		$a_00_2 = {36 33 65 33 39 32 35 61 2d 66 65 30 65 2d 34 39 62 38 2d 61 66 65 33 2d 64 30 66 31 39 64 31 39 61 30 63 64 } //1 63e3925a-fe0e-49b8-afe3-d0f19d19a0cd
		$a_00_3 = {6f 75 72 78 69 6e 2e 63 6f 6d 2f 63 66 73 } //10 ourxin.com/cfs
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //10 InternetOpenUrlA
		$a_00_5 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 } //10 GetLastActivePopup
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10+(#a_01_4  & 1)*10+(#a_00_5  & 1)*10) >=41
 
}
rule TrojanDownloader_Win32_Allsum_3{
	meta:
		description = "TrojanDownloader:Win32/Allsum,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 08 00 00 "
		
	strings :
		$a_01_0 = {25 73 73 70 6f 6f 6c 73 76 2e 65 78 65 20 2d 70 72 69 6e 74 65 72 } //4 %sspoolsv.exe -printer
		$a_01_1 = {3f 67 75 69 64 3d 25 73 26 76 65 6e 64 6f 72 3d 25 73 26 6f 73 3d 25 75 } //2 ?guid=%s&vendor=%s&os=%u
		$a_01_2 = {5c 43 6f 6e 66 69 67 5c 70 6c 75 67 69 6e 73 2e 69 6e 69 } //2 \Config\plugins.ini
		$a_01_3 = {5c 77 6d 70 64 72 6d 2e 64 6c 6c } //2 \wmpdrm.dll
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 30 45 36 37 34 35 38 38 2d 36 36 42 37 2d 34 45 31 39 2d 39 44 30 45 2d 32 30 35 33 42 38 30 30 46 36 39 46 7d } //3 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{0E674588-66B7-4E19-9D0E-2053B800F69F}
		$a_01_5 = {31 30 20 6d 69 6e 20 63 68 65 63 6b 69 6e 67 2e 2e 2e } //2 10 min checking...
		$a_01_6 = {63 61 75 73 65 20 65 76 65 6e 74 20 25 73 2e 2e 2e } //2 cause event %s...
		$a_01_7 = {70 6c 75 67 69 6e 63 61 6c 6c 5f 70 6c 75 67 69 6e 5f 6c 69 76 65 75 70 64 61 74 65 5f 63 68 65 63 6b 77 65 62 70 61 67 65 } //2 plugincall_plugin_liveupdate_checkwebpage
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=13
 
}
rule TrojanDownloader_Win32_Allsum_4{
	meta:
		description = "TrojanDownloader:Win32/Allsum,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //1 Microsoft Visual C++ Runtime Library
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {63 63 6d 64 3a 2f 2f 50 6f 70 75 70 41 44 } //1 ccmd://PopupAD
		$a_01_3 = {45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 30 45 36 37 34 35 38 38 2d 36 36 42 37 2d 34 45 31 39 2d 39 44 30 45 2d 32 30 35 33 42 38 30 30 46 36 39 46 7d } //1 Explorer\Browser Helper Objects\{0E674588-66B7-4E19-9D0E-2053B800F69F}
		$a_01_4 = {43 72 65 61 74 65 41 63 63 65 6c 65 72 61 74 6f 72 54 61 62 6c 65 41 } //1 CreateAcceleratorTableA
		$a_01_5 = {44 65 73 74 72 6f 79 41 63 63 65 6c 65 72 61 74 6f 72 54 61 62 6c 65 } //1 DestroyAcceleratorTable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}