
rule TrojanDownloader_Win32_TinyDow_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/TinyDow.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {55 72 6c 6d 6f 6e 2e 64 6c 6c } //1 Urlmon.dll
		$a_01_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //1 LoadLibraryA
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //1 URLDownloadToFileW
		$a_01_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_4 = {3a 00 2f 00 2f 00 6f 00 63 00 65 00 61 00 6e 00 6f 00 66 00 63 00 68 00 65 00 61 00 74 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 68 00 65 00 63 00 6f 00 6c 00 6f 00 72 00 79 00 65 00 6c 00 6c 00 6f 00 77 00 76 00 33 00 2f 00 6c 00 6f 00 76 00 65 00 2e 00 61 00 75 00 33 00 } //2 ://oceanofcheats.com/thecoloryellowv3/love.au3
		$a_01_5 = {3a 00 2f 00 2f 00 6f 00 63 00 65 00 61 00 6e 00 6f 00 66 00 63 00 68 00 65 00 61 00 74 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 68 00 65 00 63 00 6f 00 6c 00 6f 00 72 00 79 00 65 00 6c 00 6c 00 6f 00 77 00 76 00 33 00 2f 00 41 00 75 00 74 00 6f 00 49 00 74 00 33 00 2e 00 65 00 78 00 65 00 } //2 ://oceanofcheats.com/thecoloryellowv3/AutoIt3.exe
		$a_01_6 = {3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 76 00 65 00 2e 00 65 00 78 00 65 00 } //2 :\ProgramData\love.exe
		$a_01_7 = {3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 76 00 65 00 2e 00 61 00 75 00 33 00 } //2 :\ProgramData\love.au3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=12
 
}