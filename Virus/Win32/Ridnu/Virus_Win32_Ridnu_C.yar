
rule Virus_Win32_Ridnu_C{
	meta:
		description = "Virus:Win32/Ridnu.C,SIGNATURE_TYPE_PEHSTR,34 00 34 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 2a 2e 65 78 65 } //0a 00  \*.exe
		$a_01_1 = {44 45 55 4c 4c 45 44 4f 2d 58 2e 53 43 52 } //0a 00  DEULLEDO-X.SCR
		$a_01_2 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //0a 00  :\autorun.inf
		$a_01_3 = {5c 73 79 73 74 65 6d 33 32 5c 6c 6f 67 6f 6e 75 69 2e 73 63 72 } //0a 00  \system32\logonui.scr
		$a_01_4 = {5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 77 69 6e 61 6d 70 5c 77 69 6e 61 6d 70 } //01 00  \program files\winamp\winamp
		$a_01_5 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //01 00  \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 57 6f 72 6b 67 72 6f 75 70 43 72 61 77 6c 65 72 5c 53 68 61 72 65 73 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\WorkgroupCrawler\Shares
		$a_01_7 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_01_8 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  Toolhelp32ReadProcessMemory
	condition:
		any of ($a_*)
 
}