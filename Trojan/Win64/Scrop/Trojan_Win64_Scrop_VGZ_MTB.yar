
rule Trojan_Win64_Scrop_VGZ_MTB{
	meta:
		description = "Trojan:Win64/Scrop.VGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {4b 38 6d 4e 32 70 51 35 72 54 37 76 57 30 78 59 33 7a 41 36 62 43 39 64 45 31 66 47 34 68 4a 32 } //1 K8mN2pQ5rT7vW0xY3zA6bC9dE1fG4hJ2
		$a_01_1 = {74 69 6d 65 6f 75 74 20 2f 74 20 31 30 20 2f 6e 6f 62 72 65 61 6b 20 3e 6e 75 6c } //1 timeout /t 10 /nobreak >nul
		$a_01_2 = {64 65 6c 20 2f 66 20 2f 71 20 22 } //1 del /f /q "
		$a_01_3 = {73 74 61 72 74 20 22 22 20 22 } //1 start "" "
		$a_01_4 = {44 6f 63 75 6d 65 6e 74 73 41 70 70 44 61 74 61 41 50 50 44 41 54 41 55 53 45 52 50 52 4f 46 49 4c 45 63 6d 64 2e 65 78 65 2f 63 } //1 DocumentsAppDataAPPDATAUSERPROFILEcmd.exe/c
		$a_01_5 = {68 61 61 67 73 64 65 31 2e 6c 6e 6b } //1 haagsde1.lnk
		$a_01_6 = {2e 62 61 74 } //1 .bat
		$a_01_7 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 42 79 70 61 73 73 2d 43 6f 6d 6d 61 6e 64 } //1 powershell.exe-ExecutionPolicyBypass-Command
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 4c 6f 67 6f 6e } //1 Software\Microsoft\Windows\CurrentVersion\ExplorerLogon
		$a_00_9 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_10 = {4c 00 6f 00 63 00 61 00 6c 00 5c 00 42 00 6f 00 74 00 6b 00 69 00 6c 00 6c 00 65 00 72 00 4d 00 75 00 74 00 65 00 78 00 5f 00 76 00 31 00 } //1 Local\BotkillerMutex_v1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=11
 
}