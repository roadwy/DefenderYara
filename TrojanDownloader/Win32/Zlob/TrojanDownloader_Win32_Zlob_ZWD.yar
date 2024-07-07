
rule TrojanDownloader_Win32_Zlob_ZWD{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ZWD,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 67 61 6c 61 2e 64 6c 6c } //1 \gala.dll
		$a_00_1 = {5c 49 6e 73 74 61 6c 6c 4f 70 74 69 6f 6e 73 2e 64 6c 6c } //1 \InstallOptions.dll
		$a_00_2 = {5c 77 69 6e 69 6e 69 74 2e 69 6e 69 } //1 \wininit.ini
		$a_02_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 90 01 05 20 41 64 64 2d 6f 6e 90 00 } //1
		$a_00_4 = {25 73 5c 6c 61 25 73 25 64 2e 65 78 65 } //1 %s\la%s%d.exe
		$a_00_5 = {46 69 6e 64 46 69 72 73 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 } //1 FindFirstUrlCacheEntryA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}