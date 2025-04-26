
rule TrojanDownloader_Win32_QQHelper_KA{
	meta:
		description = "TrojanDownloader:Win32/QQHelper.KA,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 07 00 00 "
		
	strings :
		$a_00_0 = {4e 53 49 53 64 6c 2e 64 6c 6c } //10 NSISdl.dll
		$a_00_1 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //10 FindNextFileA
		$a_00_2 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //10 CreateDirectoryA
		$a_00_3 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //10 GetWindowsDirectoryA
		$a_00_4 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //10 SetClipboardData
		$a_00_5 = {71 71 68 65 6c 70 65 72 2e 63 6f 6d 2f 62 69 6e 64 73 6f 66 74 31 31 2f 62 69 6e 64 73 65 74 75 70 2e 65 78 65 } //1 qqhelper.com/bindsoft11/bindsetup.exe
		$a_02_6 = {71 71 68 65 6c 70 65 72 2e 63 6f 6d 2f 62 69 6e 64 73 6f 66 74 2f 62 69 6e 64 73 65 74 75 70 [0-08] 2e 65 78 65 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1) >=51
 
}