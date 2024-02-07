
rule TrojanDropper_Win32_QQpass_CJM{
	meta:
		description = "TrojanDropper:Win32/QQpass.CJM,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 4c 53 49 44 5c 7b 41 36 30 31 31 46 38 46 2d 41 37 46 38 2d 34 39 41 41 2d 39 41 44 41 2d 34 39 31 32 37 44 34 33 31 33 38 46 } //01 00  CLSID\{A6011F8F-A7F8-49AA-9ADA-49127D43138F
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_2 = {4e 65 77 49 6e 66 6f 2e 62 61 6b } //01 00  NewInfo.bak
		$a_01_3 = {4e 65 77 49 6e 66 6f 2e 72 78 6b } //01 00  NewInfo.rxk
		$a_01_4 = {74 69 61 6e 6c 69 61 } //01 00  tianlia
		$a_01_5 = {78 69 61 6f 67 61 6e } //01 00  xiaogan
		$a_01_6 = {48 6f 6f 6b 4f 6e } //01 00  HookOn
		$a_01_7 = {48 6f 6f 6b 4f 66 66 } //00 00  HookOff
	condition:
		any of ($a_*)
 
}