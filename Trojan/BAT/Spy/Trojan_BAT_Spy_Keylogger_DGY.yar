
rule Trojan_BAT_Spy_Keylogger_DGY{
	meta:
		description = "Trojan:BAT/Spy.Keylogger.DGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 09 00 00 05 00 "
		
	strings :
		$a_80_0 = {48 6f 6f 6b 50 72 6f 63 } //HookProc  04 00 
		$a_80_1 = {57 48 5f 4a 4f 55 52 4e 41 4c 52 45 43 4f 52 44 } //WH_JOURNALRECORD  04 00 
		$a_80_2 = {57 48 5f 4a 4f 55 52 4e 41 4c 50 4c 41 59 42 41 43 4b } //WH_JOURNALPLAYBACK  04 00 
		$a_80_3 = {57 48 5f 4b 45 59 42 4f 41 52 44 5f 4c 4c } //WH_KEYBOARD_LL  03 00 
		$a_80_4 = {4c 4c 4b 48 46 5f 49 4e 4a 45 43 54 45 44 } //LLKHF_INJECTED  03 00 
		$a_80_5 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //GetAsyncKeyState  03 00 
		$a_80_6 = {54 65 78 74 4c 6f 67 67 65 72 } //TextLogger  03 00 
		$a_80_7 = {47 65 74 57 69 6e 64 6f 77 54 65 78 74 } //GetWindowText  03 00 
		$a_80_8 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  00 00 
	condition:
		any of ($a_*)
 
}