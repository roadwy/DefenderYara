
rule TrojanDownloader_Win32_Agent_AAF{
	meta:
		description = "TrojanDownloader:Win32/Agent.AAF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 75 72 6c 63 6f 72 65 2e 65 78 65 20 2f 68 20 2f 72 20 2f 74 20 2f 62 } //01 00  \Program Files\urlcore.exe /h /r /t /b
		$a_00_1 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b } //01 00  \Internet Explorer.lnk
		$a_00_2 = {5c 48 69 64 65 44 65 73 6b 74 6f 70 49 63 6f 6e 73 5c 43 6c 61 73 73 69 63 53 74 61 72 74 4d 65 6e 75 } //01 00  \HideDesktopIcons\ClassicStartMenu
		$a_03_3 = {6a 00 6a 00 68 f5 00 00 00 90 01 01 e8 90 01 04 6a 00 6a 00 68 f5 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}