
rule TrojanDownloader_Win32_Deepdo{
	meta:
		description = "TrojanDownloader:Win32/Deepdo,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 44 4c 2f 31 2e 30 } //1 AutoDL/1.0
		$a_00_1 = {5c 44 65 65 70 64 6f 5c 44 65 65 70 64 6f 42 61 72 5c 46 61 76 6f 72 69 74 65 } //1 \Deepdo\DeepdoBar\Favorite
		$a_00_2 = {55 70 64 61 74 65 2e 65 78 65 00 } //1
		$a_00_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e } //1 http://www.
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_6 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetWindowsDirectoryA
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}