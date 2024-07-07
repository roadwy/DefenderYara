
rule PWS_Win32_OnLineGames_CRP{
	meta:
		description = "PWS:Win32/OnLineGames.CRP,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0b 00 00 "
		
	strings :
		$a_02_0 = {ff ff 68 04 01 00 00 50 6a 00 ff 15 90 01 03 00 8d 8d 90 01 02 ff ff 6a 5c 51 ff 15 90 01 03 00 83 c4 08 8b d8 90 00 } //10
		$a_00_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_00_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_00_3 = {44 6f 77 6e 6c 6f 61 64 4e 65 74 46 69 6c 65 } //1 DownloadNetFile
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41 } //1 URLDownloadToCacheFileA
		$a_00_5 = {23 33 32 37 37 30 } //1 #32770
		$a_00_6 = {39 39 39 39 39 39 39 00 } //1 㤹㤹㤹9
		$a_00_7 = {64 6c 6c 63 61 63 68 65 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 dllcache\explorer.exe
		$a_00_8 = {64 6c 6c 63 61 63 68 65 5c 63 6f 6e 69 6d 65 2e 65 78 65 } //1 dllcache\conime.exe
		$a_00_9 = {64 6c 6c 63 61 63 68 65 5c 63 74 66 6d 6f 6e 2e 65 78 65 } //1 dllcache\ctfmon.exe
		$a_00_10 = {64 6c 6c 63 61 63 68 65 5c 69 6e 74 65 72 6e 61 74 2e 65 78 65 } //1 dllcache\internat.exe
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=25
 
}