
rule Trojan_Win32_Agent{
	meta:
		description = "Trojan:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 70 2e 65 78 65 } //10 c:\windows\systemp.exe
		$a_00_1 = {63 3a 5c 77 61 62 6f 6b 2e 6c 6f 67 } //1 c:\wabok.log
		$a_00_2 = {63 3a 5c 6e 6f 69 73 2e 6c 6f 67 } //1 c:\nois.log
		$a_00_3 = {65 6d 61 69 6c 3d } //1 email=
		$a_00_4 = {63 6f 6d 70 75 74 61 64 6f 72 3d } //1 computador=
		$a_00_5 = {6e 6f 6d 66 69 6c 65 3d } //1 nomfile=
		$a_01_6 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_00_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=17
 
}
rule Trojan_Win32_Agent_2{
	meta:
		description = "Trojan:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {4f 4b 00 00 66 75 63 6b 20 4e 4f 44 33 32 20 74 77 6f 20 74 69 6d 65 73 00 00 00 00 45 52 52 4f 52 00 00 00 66 75 63 6b 20 4e 4f 44 33 32 20 66 69 72 73 74 20 74 69 6d 65 73 } //3
		$a_00_1 = {32 6b 69 6c 6c 79 6f 75 61 6c 6c } //1 2killyouall
		$a_00_2 = {53 65 72 76 65 72 20 74 6f 20 43 6c 69 65 6e 74 } //1 Server to Client
		$a_00_3 = {43 6c 69 65 6e 74 20 74 6f 20 53 65 72 76 65 72 } //1 Client to Server
		$a_02_4 = {89 5c 24 1c e8 92 12 00 00 bf ?? ?? ?? ?? 83 c9 ff 33 c0 f2 ae f7 d1 49 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 09 0c 00 00 } //1
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=7
 
}
rule Trojan_Win32_Agent_3{
	meta:
		description = "Trojan:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 50 40 00 38 50 40 00 53 74 61 72 74 00 00 00 5c 64 6f 6e 6d 2e 64 6c 6c 00 00 00 57 69 6e 73 74 61 30 5c 44 65 66 61 75 6c 74 00 20 20 2a 00 20 20 00 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 00 00 00 6a 70 67 00 9d 15 40 00 02 00 00 00 } //1
		$a_03_1 = {68 88 13 00 00 c7 44 24 ?? 01 00 00 00 c7 44 24 ?? ?? ?? ?? 00 66 89 44 24 ?? ff 15 ?? ?? ?? 00 8d 44 24 ?? 8d 4c 24 ?? 50 51 6a 00 6a 00 6a 00 6a 01 6a 00 6a 00 68 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00 5f 33 c0 5e 83 c4 ?? c2 10 00 } //1
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 6f 6e 6d 2e 64 6c 6c 20 20 53 74 61 72 74 20 20 2a } //1 rundll32.exe C:\WINDOWS\SYSTEM32\donm.dll  Start  *
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule Trojan_Win32_Agent_4{
	meta:
		description = "Trojan:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1c 00 0e 00 00 "
		
	strings :
		$a_00_0 = {73 70 69 64 65 72 2e 67 75 63 63 69 73 65 72 76 69 63 65 2e 62 69 7a } //10 spider.gucciservice.biz
		$a_00_1 = {5c 77 62 73 74 6f 72 65 2e 64 6c 6c } //10 \wbstore.dll
		$a_00_2 = {2f 64 61 74 61 2e 70 68 70 3f 75 73 65 72 3d } //1 /data.php?user=
		$a_01_3 = {26 70 61 73 73 3d } //1 &pass=
		$a_00_4 = {26 64 6f 6d 61 69 6e 3d } //1 &domain=
		$a_00_5 = {26 6c 6f 63 69 70 3d } //1 &locip=
		$a_00_6 = {26 63 70 75 6e 61 6d 65 3d } //1 &cpuname=
		$a_00_7 = {55 53 45 52 3a } //1 USER:
		$a_00_8 = {50 41 53 53 3a } //1 PASS:
		$a_00_9 = {44 4f 4d 45 4e 3a } //1 DOMEN:
		$a_00_10 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //1 Content-Type: application/x-www-form-urlencoded
		$a_00_11 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 } //1 HttpSendRequest
		$a_00_12 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //1 InternetConnectA
		$a_01_13 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_01_13  & 1)*1) >=28
 
}
rule Trojan_Win32_Agent_5{
	meta:
		description = "Trojan:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,60 00 5f 00 0f 00 00 "
		
	strings :
		$a_00_0 = {51 51 53 47 2e 65 78 65 } //10 QQSG.exe
		$a_00_1 = {68 6f 6f 6b } //10 hook
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_01_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //10 CreateRemoteThread
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //10 SetWindowsHookExA
		$a_01_6 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //10 InternetOpenUrlA
		$a_01_7 = {73 74 72 72 63 68 72 } //10 strrchr
		$a_00_8 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 54 65 73 53 61 66 65 2e 73 79 73 } //10 C:\WINDOWS\SYSTEM32\TesSafe.sys
		$a_00_9 = {68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 2f 6c 69 6e 2e 61 73 70 } //1 http://127.0.0.1/lin.asp
		$a_00_10 = {44 3a 5c 48 61 48 61 35 2e 30 5c 48 6f 75 73 72 5c 44 55 4d 4d 59 53 59 53 5c 6f 62 6a 66 72 65 5f 77 6e 65 74 5f 78 38 36 5c 69 33 38 36 5c 54 65 73 53 61 66 65 2e 70 64 62 } //1 D:\HaHa5.0\Housr\DUMMYSYS\objfre_wnet_x86\i386\TesSafe.pdb
		$a_00_11 = {53 47 4d 55 54 45 58 } //1 SGMUTEX
		$a_00_12 = {57 6f 72 6c 64 } //1 World
		$a_00_13 = {5a 6f 6e 65 2e 69 6e 69 } //1 Zone.ini
		$a_01_14 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //1 ntoskrnl.exe
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_00_8  & 1)*10+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_01_14  & 1)*1) >=95
 
}
rule Trojan_Win32_Agent_6{
	meta:
		description = "Trojan:Win32/Agent,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {49 45 48 70 72 2e 44 4c 4c } //1 IEHpr.DLL
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {00 31 2e 74 78 74 } //1
		$a_01_3 = {00 31 2e 62 6d 70 } //1
		$a_01_4 = {00 31 2e 65 78 65 } //1
		$a_01_5 = {00 31 2e 64 6c 6c } //1
		$a_01_6 = {4f 70 65 6e 53 65 72 76 69 63 65 41 } //1 OpenServiceA
		$a_01_7 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //1 OpenSCManagerA
		$a_01_8 = {4f 70 65 6e 4d 75 74 65 78 41 } //1 OpenMutexA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule Trojan_Win32_Agent_7{
	meta:
		description = "Trojan:Win32/Agent,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {31 31 36 2e 31 32 32 2e 31 33 35 2e 31 33 2f 61 63 63 65 73 73 5f 63 6f 75 6e 74 2e 68 74 6d 6c } //1 116.122.135.13/access_count.html
		$a_01_2 = {64 65 6c 65 74 65 73 65 6c 66 2e 62 61 74 } //1 deleteself.bat
		$a_01_3 = {45 78 65 63 75 74 65 5f 55 70 64 61 74 65 72 } //1 Execute_Updater
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 52 61 6e 64 6f 6d 55 72 6c 46 69 6c 65 } //1 DownloadRandomUrlFile
		$a_01_6 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_01_7 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}