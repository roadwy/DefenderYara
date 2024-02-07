
rule TrojanDownloader_Win32_SmallAgent_RT_MTB{
	meta:
		description = "TrojanDownloader:Win32/SmallAgent.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 53 79 73 74 65 6d 49 6e 66 6f } //01 00  FileSystemInfo
		$a_01_1 = {48 65 6c 70 4b 65 79 77 6f 72 64 41 74 74 72 69 62 75 74 65 } //01 00  HelpKeywordAttribute
		$a_01_2 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //01 00  HideModuleNameAttribute
		$a_01_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //0a 00  DebuggerHiddenAttribute
		$a_00_4 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //0a 00  C:\Windows\System32\svchost.exe
		$a_00_5 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 47 00 30 00 6a 00 63 00 47 00 73 00 37 00 39 00 } //00 00  https://pastebin.com/raw/G0jcGs79
	condition:
		any of ($a_*)
 
}