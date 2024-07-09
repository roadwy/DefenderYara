
rule Trojan_Win32_RedLineStealer_MB_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 fc 8a 04 18 8b 0d ?? ?? ?? ?? 88 04 19 c9 c3 } //10
		$a_01_1 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 GetThreadContext
		$a_01_2 = {47 65 74 4d 61 69 6c 73 6c 6f 74 49 6e 66 6f } //1 GetMailslotInfo
		$a_01_3 = {44 65 62 75 67 42 72 65 61 6b } //1 DebugBreak
		$a_01_4 = {50 65 72 6d 69 73 73 69 6f 6e 20 64 65 6e 69 65 64 } //1 Permission denied
		$a_01_5 = {44 65 62 75 67 53 65 74 50 72 6f 63 65 73 73 4b 69 6c 6c 4f 6e 45 78 69 74 } //1 DebugSetProcessKillOnExit
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}