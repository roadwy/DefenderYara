
rule TrojanDropper_Win32_Chayka_A{
	meta:
		description = "TrojanDropper:Win32/Chayka.A,SIGNATURE_TYPE_PEHSTR,29 00 29 00 08 00 00 "
		
	strings :
		$a_01_0 = {48 6f 6f 6b 49 6e 69 74 } //10 HookInit
		$a_01_1 = {73 76 72 68 6f 73 74 2e 65 78 65 } //10 svrhost.exe
		$a_01_2 = {64 65 6c 20 2f 46 20 22 2e 5c 25 73 } //10 del /F ".\%s
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //10 Software\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_4 = {64 62 6c 64 72 76 2e 64 6c 6c } //1 dbldrv.dll
		$a_01_5 = {64 62 78 64 72 76 2e 64 6c 6c } //1 dbxdrv.dll
		$a_01_6 = {7b 45 35 37 32 33 36 34 33 2d 34 30 41 34 2d 34 32 63 30 2d 38 37 44 35 2d 32 33 44 45 45 45 30 42 32 43 35 46 7d } //1 {E5723643-40A4-42c0-87D5-23DEEE0B2C5F}
		$a_01_7 = {7b 36 34 44 34 35 41 39 33 2d 30 30 44 44 2d 34 31 63 62 2d 41 31 38 37 2d 46 46 30 32 41 31 35 41 45 33 32 42 7d } //1 {64D45A93-00DD-41cb-A187-FF02A15AE32B}
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=41
 
}