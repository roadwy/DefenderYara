
rule Trojan_Win32_CryptInject_PACG_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PACG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 61 73 6b 6d 67 72 2e 65 78 65 } //01 00  taskkill /f /im taskmgr.exe
		$a_01_1 = {52 45 47 20 41 44 44 20 68 6b 63 75 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 73 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 20 2f 74 20 72 65 67 5f 64 77 6f 72 64 20 2f 64 20 31 20 2f 66 } //01 00  REG ADD hkcu\Software\Microsoft\Windows\CurrentVersion\policies\system /v DisableTaskMgr /t reg_dword /d 1 /f
		$a_01_2 = {5b 2b 5d 20 43 48 41 4e 47 49 4e 47 20 57 41 4c 4c 50 41 50 45 52 } //01 00  [+] CHANGING WALLPAPER
		$a_01_3 = {6d 61 6c 64 65 76 2e 70 64 62 } //01 00  maldev.pdb
		$a_01_4 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 41 00 73 00 73 00 69 00 67 00 6e 00 65 00 64 00 41 00 63 00 63 00 65 00 73 00 73 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00  SOFTWARE\Microsoft\Windows\AssignedAccessConfiguration
	condition:
		any of ($a_*)
 
}