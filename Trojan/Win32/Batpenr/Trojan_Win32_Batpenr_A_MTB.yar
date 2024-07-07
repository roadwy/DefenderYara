
rule Trojan_Win32_Batpenr_A_MTB{
	meta:
		description = "Trojan:Win32/Batpenr.A!MTB,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 66 20 25 63 72 25 3d 3d 32 38 20 63 6f 70 79 20 25 74 65 6d 70 25 5c 6f 6e 65 2e 72 74 66 20 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 44 65 73 6b 74 6f 70 5c 4f 50 45 4e 4d 45 4f 50 45 4e 4d 45 4f 50 45 4e 4d 45 4f 50 45 4e 4d 45 4f 50 45 4e } //10 if %cr%==28 copy %temp%\one.rtf %userprofile%\Desktop\OPENMEOPENMEOPENMEOPENMEOPEN
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 taskkill /f /im explorer.exe
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 61 73 6b 6d 67 72 2e 65 78 65 } //1 taskkill /f /im taskmgr.exe
		$a_01_3 = {73 68 75 74 64 6f 77 6e 20 2f 66 20 2f 72 20 2f 74 20 30 } //1 shutdown /f /r /t 0
		$a_01_4 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 44 65 73 6b 74 6f 70 5c 2a } //1 del /f /s /q %userprofile%\Desktop\*
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}