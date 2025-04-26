
rule Trojan_BAT_LockScreen_EA_MTB{
	meta:
		description = "Trojan:BAT/LockScreen.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 } //1 Ransomware
		$a_81_1 = {57 69 6e 6c 6f 63 6b 65 72 } //1 Winlocker
		$a_81_2 = {41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 61 72 65 20 45 6e 63 72 79 70 74 65 64 } //1 All Your Files are Encrypted
		$a_81_3 = {52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //1 Ransomware.pdb
		$a_81_4 = {41 4c 4c 20 59 4f 55 52 20 44 41 54 41 20 48 41 56 45 20 42 45 45 4e 20 44 45 4c 45 54 45 44 20 42 59 20 4e 4f 54 48 49 4e 47 53 4f 55 4c } //1 ALL YOUR DATA HAVE BEEN DELETED BY NOTHINGSOUL
		$a_81_5 = {63 6d 64 2e 65 78 65 } //1 cmd.exe
		$a_81_6 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 26 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 61 73 6b 6d 67 72 2e 65 78 65 } //1 /c taskkill /f /im explorer.exe & taskkill /f /im taskmgr.exe
		$a_81_7 = {2f 63 20 73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 74 20 30 } //1 /c shutdown /r /t 0
		$a_81_8 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_9 = {44 45 43 52 59 50 54 20 46 49 4c 45 53 } //1 DECRYPT FILES
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}