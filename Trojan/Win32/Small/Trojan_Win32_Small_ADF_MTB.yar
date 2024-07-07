
rule Trojan_Win32_Small_ADF_MTB{
	meta:
		description = "Trojan:Win32/Small.ADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 0a 00 00 "
		
	strings :
		$a_02_0 = {8b c6 0d 11 47 00 00 c1 e0 10 0b f0 89 35 90 01 04 f7 d6 89 35 90 01 04 5e 5f 5b c9 c3 90 00 } //5
		$a_80_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //URLDownloadToFileA  4
		$a_80_2 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 } //DeleteUrlCacheEntry  4
		$a_80_3 = {50 72 6f 63 65 73 73 49 64 54 6f 53 65 73 73 69 6f 6e 49 64 } //ProcessIdToSessionId  3
		$a_80_4 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //GetTempPathA  3
		$a_80_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  2
		$a_80_6 = {44 65 63 6f 64 65 50 6f 69 6e 74 65 72 } //DecodePointer  2
		$a_80_7 = {57 54 53 51 75 65 72 79 55 73 65 72 54 6f 6b 65 6e } //WTSQueryUserToken  2
		$a_80_8 = {49 73 4e 65 74 77 6f 72 6b 41 6c 69 76 65 } //IsNetworkAlive  2
		$a_80_9 = {47 65 74 50 72 6f 63 65 73 73 49 6d 61 67 65 46 69 6c 65 4e 61 6d 65 41 } //GetProcessImageFileNameA  2
	condition:
		((#a_02_0  & 1)*5+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2+(#a_80_9  & 1)*2) >=29
 
}