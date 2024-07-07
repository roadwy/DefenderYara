
rule Trojan_BAT_Spy_Keylogger_ADK{
	meta:
		description = "Trojan:BAT/Spy.Keylogger.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 12 00 08 00 00 "
		
	strings :
		$a_80_0 = {6d 79 6b 65 79 6c 6f 67 67 65 72 } //mykeylogger  5
		$a_80_1 = {4c 6f 77 4c 65 76 65 6c 4b 65 79 62 6f 61 72 64 50 72 6f 63 } //LowLevelKeyboardProc  5
		$a_80_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6d 79 6c 6f 67 5f 61 72 63 68 69 76 65 2e 74 78 74 } //C:\ProgramData\mylog_archive.txt  5
		$a_80_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //CallNextHookEx  4
		$a_80_4 = {48 6f 6f 6b 43 61 6c 6c 62 61 63 6b } //HookCallback  4
		$a_80_5 = {6d 79 6c 6f 67 2e 74 78 74 } //mylog.txt  4
		$a_80_6 = {4d 41 58 5f 4b 45 59 53 54 52 4f 4b 45 53 } //MAX_KEYSTROKES  3
		$a_80_7 = {6d 61 6c 77 61 72 65 2e 61 74 74 61 63 6b } //malware.attack  3
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4+(#a_80_5  & 1)*4+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=18
 
}