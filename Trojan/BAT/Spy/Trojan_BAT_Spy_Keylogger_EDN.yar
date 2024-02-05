
rule Trojan_BAT_Spy_Keylogger_EDN{
	meta:
		description = "Trojan:BAT/Spy.Keylogger.EDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 08 00 00 05 00 "
		
	strings :
		$a_80_0 = {48 6f 6f 6b 43 61 6c 6c 62 61 63 6b } //HookCallback  05 00 
		$a_80_1 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //CallNextHookEx  04 00 
		$a_80_2 = {5c 6c 6f 67 2e 74 78 74 } //\log.txt  04 00 
		$a_80_3 = {4c 6f 77 4c 65 76 65 6c 4b 65 79 62 6f 61 72 64 50 72 6f 63 } //LowLevelKeyboardProc  04 00 
		$a_80_4 = {57 48 5f 4b 45 59 42 4f 41 52 44 5f 4c 4c } //WH_KEYBOARD_LL  04 00 
		$a_80_5 = {57 4d 5f 4b 45 59 44 4f 57 4e } //WM_KEYDOWN  04 00 
		$a_80_6 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  03 00 
		$a_80_7 = {53 74 72 65 61 6d 57 72 69 74 65 72 } //StreamWriter  00 00 
	condition:
		any of ($a_*)
 
}