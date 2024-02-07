
rule TrojanDropper_Win32_QQpass_CJN{
	meta:
		description = "TrojanDropper:Win32/QQpass.CJN,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1a 00 0e 00 00 14 00 "
		
	strings :
		$a_01_0 = {43 4c 53 49 44 5c 7b 46 33 44 30 44 34 32 32 2d 43 45 36 44 2d 34 37 42 33 2d 39 43 45 36 2d 43 35 34 44 44 36 33 46 31 41 44 42 7d } //01 00  CLSID\{F3D0D422-CE6D-47B3-9CE6-C54DD63F1ADB}
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //02 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_00_2 = {71 71 67 73 45 78 65 } //02 00  qqgsExe
		$a_00_3 = {71 71 67 73 44 6c 6c } //01 00  qqgsDll
		$a_01_4 = {4d 73 67 48 6f 6f 6b 4f 66 66 } //01 00  MsgHookOff
		$a_01_5 = {4d 73 67 48 6f 6f 6b 4f 6e } //01 00  MsgHookOn
		$a_00_6 = {3a 74 72 79 } //01 00  :try
		$a_00_7 = {64 65 6c 20 22 } //01 00  del "
		$a_00_8 = {69 66 20 65 78 69 73 74 20 22 } //01 00  if exist "
		$a_00_9 = {20 67 6f 74 6f 20 74 72 79 } //01 00   goto try
		$a_00_10 = {64 65 6c 20 25 30 } //02 00  del %0
		$a_00_11 = {51 51 5f 47 75 69 53 68 6f 75 } //02 00  QQ_GuiShou
		$a_00_12 = {4d 72 53 6f 66 74 2e 62 61 6b } //02 00  MrSoft.bak
		$a_00_13 = {4d 72 53 6f 66 74 2e 73 79 73 } //00 00  MrSoft.sys
	condition:
		any of ($a_*)
 
}