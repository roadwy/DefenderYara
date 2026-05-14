
rule Backdoor_Win32_CotxRat_AR_AMTB{
	meta:
		description = "Backdoor:Win32/CotxRat.AR!AMTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 5f 41 70 70 44 61 74 61 20 3d 20 25 73 } //1 SHGetFolderPath_AppData = %s
		$a_01_1 = {73 74 61 72 74 20 46 61 6b 65 52 75 6e 20 70 52 65 6d 6f 74 65 41 64 64 72 65 73 73 20 3d 3d 20 4e 55 4c 4c } //1 start FakeRun pRemoteAddress == NULL
		$a_01_2 = {53 74 61 72 74 52 75 6e 46 61 6b 65 45 78 65 57 6f 72 6b } //1 StartRunFakeExeWork
		$a_01_3 = {73 74 61 72 74 20 46 61 6b 65 52 75 6e 20 25 73 } //1 start FakeRun %s
		$a_01_4 = {45 6e 74 65 72 49 6e 74 6f 20 41 6e 74 69 41 76 5f 53 74 61 72 74 52 75 6e 46 61 6b 65 45 78 65 57 6f 72 6b } //1 EnterInto AntiAv_StartRunFakeExeWork
		$a_01_5 = {73 7a 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 46 75 6c 6c 50 61 74 68 20 21 3d 20 73 7a 45 78 65 50 61 74 68 5f 52 65 61 6c 20 6f 72 20 73 7a 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 46 75 6c 6c 50 61 74 68 20 21 3d 20 73 7a 45 78 65 50 61 74 68 5f 52 65 61 6c 5f 50 72 6f 67 72 61 6d 46 69 6c 65 73 } //1 szCurrentProcessFullPath != szExePath_Real or szCurrentProcessFullPath != szExePath_Real_ProgramFiles
		$a_01_6 = {43 72 65 61 74 65 54 68 72 65 61 64 3a 20 41 6e 74 69 44 65 62 75 67 } //1 CreateThread: AntiDebug
		$a_01_7 = {41 6e 74 69 41 76 5f 53 74 61 72 74 52 75 6e 46 61 6b 65 45 78 65 57 6f 72 6b 20 53 74 61 72 74 } //1 AntiAv_StartRunFakeExeWork Start
		$a_01_8 = {64 65 63 72 79 70 74 20 70 61 73 73 77 64 3a 25 73 } //1 decrypt passwd:%s
		$a_01_9 = {74 61 6b 65 6f 77 6e 20 2f 46 20 22 25 73 22 } //1 takeown /F "%s"
		$a_01_10 = {64 65 6c 20 22 25 73 22 20 2f 71 20 2f 66 } //1 del "%s" /q /f
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}