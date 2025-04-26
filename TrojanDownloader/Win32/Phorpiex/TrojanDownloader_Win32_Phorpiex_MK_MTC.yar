
rule TrojanDownloader_Win32_Phorpiex_MK_MTC{
	meta:
		description = "TrojanDownloader:Win32/Phorpiex.MK!MTC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {25 6c 73 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 } //1 %ls:Zone.Identifier
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
		$a_81_2 = {2f 63 20 73 74 61 72 74 20 5f 5f 20 26 20 5f 5f 5c 44 72 69 76 65 4d 67 72 2e 65 78 65 20 26 20 65 78 69 74 } //1 /c start __ & __\DriveMgr.exe & exit
		$a_81_3 = {25 73 5c 25 73 5c 44 72 69 76 65 4d 67 72 2e 65 78 65 } //1 %s\%s\DriveMgr.exe
		$a_81_4 = {68 74 74 70 3a 2f 2f 77 6f 72 6d 2e 77 73 } //1 http://worm.ws
		$a_81_5 = {68 74 74 70 3a 2f 2f 74 73 72 76 31 2e 77 73 } //1 http://tsrv1.ws
		$a_81_6 = {73 76 63 68 6f 73 74 2e 65 78 65 } //1 svchost.exe
		$a_81_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=6
 
}