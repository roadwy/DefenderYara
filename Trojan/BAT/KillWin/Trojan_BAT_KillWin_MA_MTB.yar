
rule Trojan_BAT_KillWin_MA_MTB{
	meta:
		description = "Trojan:BAT/KillWin.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {48 00 41 00 43 00 4b 00 45 00 44 00 } //1 HACKED
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_2 = {2f 00 6b 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 20 00 26 00 26 00 20 00 65 00 78 00 69 00 74 00 } //1 /k taskkill /f /im taskmgr.exe && exit
		$a_01_3 = {73 79 73 74 65 6d 5f 64 65 73 74 72 6f 79 } //1 system_destroy
		$a_01_4 = {53 74 61 72 74 5f 42 53 4f 44 } //1 Start_BSOD
		$a_01_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {45 6e 74 65 72 44 65 62 75 67 4d 6f 64 65 } //1 EnterDebugMode
		$a_01_7 = {48 00 61 00 6c 00 6c 00 6f 00 2c 00 20 00 49 00 74 00 20 00 6c 00 6f 00 6f 00 6b 00 73 00 20 00 6c 00 69 00 6b 00 65 00 20 00 79 00 6f 00 75 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 76 00 69 00 72 00 75 00 73 00 20 00 61 00 6e 00 64 00 20 00 79 00 6f 00 75 00 72 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 69 00 73 00 20 00 6f 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 72 00 69 00 73 00 6b 00 21 00 } //1 Hallo, It looks like you downloaded virus and your system is on your risk!
		$a_01_8 = {41 00 6e 00 64 00 20 00 69 00 74 00 27 00 73 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 61 00 75 00 6c 00 74 00 } //1 And it's your fault
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}