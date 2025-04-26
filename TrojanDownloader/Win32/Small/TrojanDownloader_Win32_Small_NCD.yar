
rule TrojanDownloader_Win32_Small_NCD{
	meta:
		description = "TrojanDownloader:Win32/Small.NCD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {40 00 6a 00 68 00 00 02 00 e8 ?? ?? 00 00 83 f8 00 0f ?? ?? ?? ?? ?? 68 ?? ?? 40 00 6a 00 68 ?? ?? 40 00 e8 } //1
		$a_00_1 = {2f 63 20 64 65 6c 20 25 73 2e 65 78 65 } //1 /c del %s.exe
		$a_00_2 = {43 72 65 61 74 65 4d 75 74 65 78 } //1 CreateMutex
		$a_00_3 = {57 69 6e 45 78 65 63 } //1 WinExec
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}