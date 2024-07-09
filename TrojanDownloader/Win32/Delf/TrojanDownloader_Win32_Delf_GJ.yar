
rule TrojanDownloader_Win32_Delf_GJ{
	meta:
		description = "TrojanDownloader:Win32/Delf.GJ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
		$a_00_2 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 } //1 DeleteUrlCacheEntry
		$a_02_3 = {2f 6d 79 6c 69 73 74 2e 61 73 70 3f 76 65 72 3d [0-08] 26 74 67 69 64 3d [0-08] 26 61 64 64 72 65 73 73 3d 30 30 2d 30 30 2d 30 30 2d 30 30 } //1
		$a_02_4 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 00 00 00 ff ff ff ff ?? 00 00 00 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 } //1
		$a_02_5 = {64 65 6c 61 79 [0-0f] 72 75 6e [0-30] 68 74 74 70 3a 2f 2f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}