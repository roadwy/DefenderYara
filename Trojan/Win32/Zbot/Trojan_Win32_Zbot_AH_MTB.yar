
rule Trojan_Win32_Zbot_AH_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 65 00 61 00 72 00 63 00 68 00 41 00 70 00 70 00 2e 00 65 00 78 00 65 00 } //2 c:\windows\SearchApp.exe
		$a_01_1 = {71 00 77 00 65 00 72 00 32 00 33 00 2e 00 63 00 6f 00 6d 00 2f 00 44 00 4f 00 57 00 4e 00 2f 00 41 00 31 00 2e 00 65 00 78 00 65 00 } //2 qwer23.com/DOWN/A1.exe
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //1 URLDownloadToFileW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}