
rule Worm_Win32_Autorun_FE{
	meta:
		description = "Worm:Win32/Autorun.FE,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_1 = {55 73 65 72 69 6e 69 74 } //1 Userinit
		$a_01_2 = {53 2d 31 2d 35 2d 32 31 2d 34 33 35 31 37 34 36 34 34 37 2d 32 38 33 36 37 34 31 37 35 2d 37 38 33 35 32 35 31 33 34 35 2d 35 30 30 } //1 S-1-5-21-4351746447-283674175-7835251345-500
		$a_01_3 = {74 61 73 6b 6d 67 72 2e 65 78 65 } //1 taskmgr.exe
		$a_01_4 = {6d 6a 33 36 2e 65 78 65 } //1 mj36.exe
		$a_01_5 = {41 75 74 6f 52 75 6e 2e 69 6e 66 } //1 AutoRun.inf
		$a_01_6 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_01_7 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 63 6f 6d 6d 61 6e 64 } //1 shell\explore\command
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}