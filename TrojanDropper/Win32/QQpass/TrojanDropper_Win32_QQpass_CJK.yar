
rule TrojanDropper_Win32_QQpass_CJK{
	meta:
		description = "TrojanDropper:Win32/QQpass.CJK,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 09 00 00 "
		
	strings :
		$a_00_0 = {43 4c 53 49 44 5c 7b 30 38 33 31 35 43 31 41 2d 39 42 41 39 2d 34 42 37 43 2d 41 34 33 32 2d 32 36 38 38 } //10 CLSID\{08315C1A-9BA9-4B7C-A432-2688
		$a_00_1 = {78 69 61 72 61 6e } //1 xiaran
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_3 = {5f 78 72 2e 62 61 74 } //1 _xr.bat
		$a_01_4 = {4a 6d 70 48 6f 6f 6b 4f 66 66 } //1 JmpHookOff
		$a_01_5 = {4a 6d 70 48 6f 6f 6b 4f 6e } //1 JmpHookOn
		$a_00_6 = {3a 74 72 79 } //1 :try
		$a_00_7 = {67 6f 74 6f 20 74 72 79 } //1 goto try
		$a_00_8 = {69 66 20 65 78 69 73 74 20 22 } //1 if exist "
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=15
 
}