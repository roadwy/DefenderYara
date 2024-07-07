
rule Trojan_Win32_Babadeda_RPD_MTB{
	meta:
		description = "Trojan:Win32/Babadeda.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {63 6f 70 79 20 64 65 6c 65 74 65 2e 65 78 65 20 43 3a 5c 57 49 4e 44 4f 57 53 } //1 copy delete.exe C:\WINDOWS
		$a_01_1 = {63 6f 70 79 20 65 78 70 61 6e 64 2e 65 78 65 20 43 3a 5c 57 49 4e 44 4f 57 53 } //1 copy expand.exe C:\WINDOWS
		$a_01_2 = {65 63 68 6f 20 79 20 7c 20 72 65 67 20 61 64 64 } //1 echo y | reg add
		$a_01_3 = {4e 6f 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c } //1 NoControlPanel
		$a_01_4 = {4e 6f 56 69 65 77 4f 6e 44 72 69 76 65 } //1 NoViewOnDrive
		$a_01_5 = {4e 6f 44 72 69 76 65 54 79 70 65 41 75 74 6f 52 75 6e } //1 NoDriveTypeAutoRun
		$a_01_6 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_01_7 = {64 69 73 61 62 6c 65 72 65 67 69 73 74 72 79 74 6f 6f 6c 73 } //1 disableregistrytools
		$a_01_8 = {44 69 73 61 62 6c 65 43 4d 44 } //1 DisableCMD
		$a_01_9 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 taskkill /f /im explorer.exe
		$a_01_10 = {73 74 61 72 74 20 72 61 6e 64 6f 6d 2e 62 61 74 } //1 start random.bat
		$a_01_11 = {73 74 61 72 74 20 64 65 6c 65 74 65 2e 65 78 65 } //1 start delete.exe
		$a_01_12 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 63 6d 64 2e 65 78 65 } //1 taskkill /f /im cmd.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}