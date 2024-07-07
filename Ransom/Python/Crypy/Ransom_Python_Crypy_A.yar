
rule Ransom_Python_Crypy_A{
	meta:
		description = "Ransom:Python/Crypy.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 69 63 74 69 6d 2e 70 68 70 3f 69 6e 66 6f 3d 73 04 00 00 00 26 69 70 3d 74 04 00 00 00 78 5f 49 44 74 05 00 00 00 78 5f 55 44 50 74 05 00 } //1
		$a_01_1 = {65 6e 63 72 79 70 74 6f 72 2e 70 79 77 74 0d 00 00 00 64 65 6c 65 74 65 5f 73 68 61 64 6f 77 } //1
		$a_01_2 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 28 05 00 00 00 52 19 00 00 00 74 09 00 00 00 63 6f 6e 66 69 67 75 72 6c 74 0b 00 00 00 67 6c 6f 62 5f 63 6f 6e 66 69 67 74 03 00 00 00 6b 65 79 74 0b 00 00 00 6e 65 77 66 69 6c 65 6e 61 6d 65 } //1
		$a_01_3 = {76 69 63 74 69 6d 28 03 00 00 00 74 03 00 00 00 64 69 72 74 03 00 00 00 65 78 74 74 05 00 00 00 66 69 6c 65 73 28 00 00 00 00 28 00 00 00 00 73 0d 00 00 00 65 6e 63 72 79 70 74 6f 72 2e 70 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}
rule Ransom_Python_Crypy_A_2{
	meta:
		description = "Ransom:Python/Crypy.A,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 73 73 } //1 bcdedit /set {default} bootstatuspolicy ignoreallfailuresss
		$a_01_1 = {52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 76 20 44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 20 2f 64 20 31 } //1 REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v DisableRegistryTools /d 1
		$a_01_2 = {52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 20 2f 64 20 31 } //1 REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v DisableTaskMgr /d 1
		$a_01_3 = {52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 76 20 44 69 73 61 62 6c 65 43 4d 44 20 2f 64 20 31 } //1 REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v DisableCMD /d 1
		$a_01_4 = {52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 76 20 4e 6f 52 75 6e 20 2f 64 20 31 } //1 REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /t REG_DWORD /v NoRun /d 1
		$a_01_5 = {44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 Delete Shadows /All /Quiet
		$a_01_6 = {57 69 6e 5f 65 6e 63 72 79 70 74 6f 72 2e 70 79 77 } //1 Win_encryptor.pyw
		$a_01_7 = {52 45 47 20 41 44 44 20 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 20 2f 76 20 66 44 65 6e 79 54 53 43 6f 6e 6e 65 63 74 69 6f 6e 73 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 } //1 REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0
		$a_01_8 = {63 72 65 61 74 65 5f 72 65 6d 6f 74 65 5f 64 65 73 6b 74 6f 70 2e } //1 create_remote_desktop.
		$a_01_9 = {5f 52 45 41 44 4d 45 5f 46 4f 52 5f 44 45 43 52 59 50 54 2e 74 } //1 _README_FOR_DECRYPT.t
		$a_01_10 = {21 20 21 20 21 20 57 20 41 52 20 4e 20 49 20 4e 20 47 20 21 20 21 20 21 } //1 ! ! ! W AR N I N G ! ! !
		$a_01_11 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 } //1 All your files are encrypted by
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}