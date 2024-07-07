
rule Backdoor_Win32_DarkRAT_AR_MTB{
	meta:
		description = "Backdoor:Win32/DarkRAT.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 08 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 31 20 2d 77 20 33 30 30 30 20 3e 20 4e 75 6c 20 26 20 44 65 6c 20 2f 66 20 2f 71 20 22 25 73 22 } //cmd.exe /C ping 127.0.0.1 -n 1 -w 3000 > Nul & Del /f /q "%s"  10
		$a_80_1 = {63 6d 64 2e 65 78 65 20 2f 6b 20 73 74 61 72 74 } //cmd.exe /k start  10
		$a_80_2 = {53 65 74 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 43 6f 6d 70 75 74 65 72 4e 61 6d 65 20 26 20 22 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29 } //Set objWMIService = GetObject("winmgmts:\\" & sComputerName & "\root\cimv2")  20
		$a_80_3 = {73 51 75 65 72 79 20 3d 20 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 } //sQuery = "SELECT * FROM Win32_Process"  1
		$a_80_4 = {53 65 74 20 6f 62 6a 53 68 65 6c 6c 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //Set objShell = WScript.CreateObject("WScript.Shell")  1
		$a_80_5 = {57 53 63 72 69 70 74 2e 53 6c 65 65 70 20 31 30 30 30 } //WScript.Sleep 1000  1
		$a_80_6 = {72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 32 } //root\SecurityCenter2  10
		$a_80_7 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //Select * From AntiVirusProduct  10
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*20+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*10+(#a_80_7  & 1)*10) >=42
 
}