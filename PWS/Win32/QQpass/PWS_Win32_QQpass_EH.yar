
rule PWS_Win32_QQpass_EH{
	meta:
		description = "PWS:Win32/QQpass.EH,SIGNATURE_TYPE_PEHSTR,20 00 1e 00 12 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 54 45 4e 43 45 4e 54 5c } //10 Software\TENCENT\
		$a_01_1 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 22 20 2f 76 20 41 70 70 49 6e 69 74 5f 44 4c 4c 73 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 20 22 25 73 22 20 2f 66 20 20 } //4 reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t reg_sz /d "%s" /f  
		$a_01_2 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 22 20 2f 76 20 4c 6f 61 64 41 70 70 49 6e 69 74 5f 44 4c 4c 73 20 2f 74 20 72 65 67 5f 64 77 6f 72 64 20 2f 64 20 31 20 2f 66 20 } //4 reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t reg_dword /d 1 /f 
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 25 73 20 2f 74 } //4 taskkill /f /im %s /t
		$a_01_4 = {64 65 6c 20 25 30 } //4 del %0
		$a_01_5 = {68 70 69 67 5f 57 53 32 2e 64 61 74 } //1 hpig_WS2.dat
		$a_01_6 = {72 78 69 6e 67 2e 62 61 74 } //1 rxing.bat
		$a_01_7 = {68 65 6c 6c 62 6f 79 37 2e } //1 hellboy7.
		$a_01_8 = {68 65 78 69 6c 2e 64 6c 6c } //1 hexil.dll
		$a_01_9 = {73 68 65 6e 67 6f 64 2e 64 61 74 } //1 shengod.dat
		$a_01_10 = {45 53 45 54 4e 4f 44 2e 62 61 74 } //1 ESETNOD.bat
		$a_01_11 = {66 61 6b 65 77 73 32 68 65 6c 70 2e 64 6c 6c } //1 fakews2help.dll
		$a_01_12 = {6b 78 65 73 63 6f 72 65 2e 65 78 65 } //1 kxescore.exe
		$a_01_13 = {6d 73 73 6f 66 74 2e 62 61 74 } //1 mssoft.bat
		$a_01_14 = {5c 64 6c 6c 63 61 63 68 65 5c } //1 \dllcache\
		$a_01_15 = {4a 6f 61 63 68 69 6d 50 65 69 70 65 72 2e 64 61 74 } //1 JoachimPeiper.dat
		$a_01_16 = {63 3a 5c 64 64 2e 62 61 74 } //1 c:\dd.bat
		$a_01_17 = {68 65 6c 6c 70 2e 64 6c 6c } //1 hellp.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=30
 
}