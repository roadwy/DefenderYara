
rule TrojanDropper_Win32_QQpass_CJL{
	meta:
		description = "TrojanDropper:Win32/QQpass.CJL,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {43 4c 53 49 44 5c 7b 30 36 41 34 38 41 44 39 2d 46 46 35 37 2d 34 45 37 33 2d 39 33 37 42 2d 42 34 39 33 } //01 00  CLSID\{06A48AD9-FF57-4E73-937B-B493
		$a_00_1 = {57 69 6e 49 6e 66 6f 2e 72 78 6b } //01 00  WinInfo.rxk
		$a_00_2 = {57 69 6e 49 6e 66 6f 2e 62 6b 6b } //01 00  WinInfo.bkk
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_4 = {4d 73 67 48 6f 6f 6b 4f 66 66 } //01 00  MsgHookOff
		$a_01_5 = {4d 73 67 48 6f 6f 6b 4f 6e } //01 00  MsgHookOn
		$a_01_6 = {63 6f 36 6d 65 69 79 } //01 00  co6meiy
		$a_01_7 = {65 61 37 63 75 6f 61 } //00 00  ea7cuoa
	condition:
		any of ($a_*)
 
}