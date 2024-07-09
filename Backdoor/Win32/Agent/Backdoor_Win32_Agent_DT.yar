
rule Backdoor_Win32_Agent_DT{
	meta:
		description = "Backdoor:Win32/Agent.DT,SIGNATURE_TYPE_PEHSTR_EXT,ffffff83 00 ffffff83 00 0a 00 00 "
		
	strings :
		$a_02_0 = {0f be 34 1f 83 fe 20 7c 22 83 fe 7e 7f 1d e8 ?? ?? ?? ?? 8d 0c 40 c1 e1 05 8d 44 31 ?? b9 5f 00 00 00 99 f7 f9 80 c2 20 88 14 1f 47 3b fd 7c } //100
		$a_00_1 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 20 30 20 2d 66 } //10 shutdown -s -t 0 -f
		$a_00_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //10 Microsoft Corporation
		$a_00_3 = {50 73 53 65 74 4c 6f 61 64 49 6d 61 67 65 4e 6f 74 69 66 79 52 6f 75 74 69 6e 65 } //10 PsSetLoadImageNotifyRoutine
		$a_00_4 = {73 69 6e 2e 62 61 74 } //1 sin.bat
		$a_00_5 = {64 65 6c 20 25 30 } //1 del %0
		$a_00_6 = {64 65 6c 20 22 25 73 22 20 } //1 del "%s" 
		$a_00_7 = {63 64 20 20 43 3a 5c } //1 cd  C:\
		$a_00_8 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f } //1 if exist "%s" goto
		$a_00_9 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=131
 
}