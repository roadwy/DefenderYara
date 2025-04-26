
rule BrowserModifier_Win32_MegaSearch{
	meta:
		description = "BrowserModifier:Win32/MegaSearch,SIGNATURE_TYPE_PEHSTR_EXT,23 00 22 00 0b 00 00 "
		
	strings :
		$a_01_0 = {7b 38 42 43 36 33 34 36 42 2d 46 46 42 30 2d 34 34 33 35 2d 41 43 45 33 2d 46 41 43 41 36 43 44 37 37 38 31 36 7d } //20 {8BC6346B-FFB0-4435-ACE3-FACA6CD77816}
		$a_01_1 = {53 65 61 72 63 68 41 73 73 69 73 74 61 6e 74 } //5 SearchAssistant
		$a_01_2 = {4d 65 67 61 48 6f 73 74 } //5 MegaHost
		$a_01_3 = {52 70 63 53 74 72 69 6e 67 46 72 65 65 41 } //2 RpcStringFreeA
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41 } //1 URLDownloadToCacheFileA
		$a_00_5 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
		$a_01_6 = {65 78 65 63 55 72 6c } //1 execUrl
		$a_00_7 = {43 6f 43 72 65 61 74 65 47 75 69 64 } //1 CoCreateGuid
		$a_00_8 = {55 75 69 64 54 6f 53 74 72 69 6e 67 41 } //1 UuidToStringA
		$a_00_9 = {43 72 65 61 74 65 46 69 6c 65 41 } //1 CreateFileA
		$a_01_10 = {57 72 69 74 65 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 69 6e 67 41 } //1 WritePrivateProfileStringA
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1) >=34
 
}
rule BrowserModifier_Win32_MegaSearch_2{
	meta:
		description = "BrowserModifier:Win32/MegaSearch,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 09 00 00 "
		
	strings :
		$a_01_0 = {4d 65 67 61 48 6f 73 74 2e 64 6c 6c } //5 MegaHost.dll
		$a_01_1 = {68 74 74 70 3a 2f 2f 36 39 2e 35 30 2e 31 36 34 2e 31 31 2f 76 31 2f 6d 68 2e 70 68 70 3f 70 69 64 3d 25 73 26 63 69 64 3d 25 73 26 70 3d 25 73 26 74 3d 25 73 26 76 68 3d 25 69 26 76 74 3d 25 69 } //5 http://69.50.164.11/v1/mh.php?pid=%s&cid=%s&p=%s&t=%s&vh=%i&vt=%i
		$a_01_2 = {68 74 74 70 3a 2f 2f 62 65 73 74 2d 73 65 61 72 63 68 2e 75 73 } //5 http://best-search.us
		$a_01_3 = {4d 65 67 61 54 6c 62 72 2e 64 6c 6c } //5 MegaTlbr.dll
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 Software\Microsoft\Internet Explorer\Main
		$a_00_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41 } //1 URLDownloadToCacheFileA
		$a_00_6 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 } //1 DeleteUrlCacheEntry
		$a_01_7 = {47 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 41 } //1 GetUrlCacheEntryInfoA
		$a_01_8 = {53 65 61 72 63 68 41 73 73 69 73 74 61 6e 74 } //1 SearchAssistant
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=24
 
}