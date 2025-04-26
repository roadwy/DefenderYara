
rule Trojan_BAT_Masslogger_GG_MTB{
	meta:
		description = "Trojan:BAT/Masslogger.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {6d 61 73 73 6c 6f 67 67 65 72 } //masslogger  15
		$a_80_1 = {50 61 73 73 77 6f 72 64 } //Password  1
		$a_80_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //SetWindowsHookEx  1
		$a_80_3 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //GetKeyboardState  1
		$a_80_4 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //CallNextHookEx  1
		$a_80_5 = {48 4f 4f 4b 2f 4d 45 4d 4f 52 59 36 } //HOOK/MEMORY6  1
	condition:
		((#a_80_0  & 1)*15+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=18
 
}
rule Trojan_BAT_Masslogger_GG_MTB_2{
	meta:
		description = "Trojan:BAT/Masslogger.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0c 00 00 "
		
	strings :
		$a_80_0 = {4d 61 73 73 4c 6f 67 67 65 72 42 69 6e } //MassLoggerBin  20
		$a_80_1 = {43 6f 73 74 75 72 61 } //Costura  1
		$a_80_2 = {57 4d 5f 43 4c 49 50 42 4f 41 52 44 55 50 44 41 54 45 } //WM_CLIPBOARDUPDATE  1
		$a_80_3 = {57 48 4b 45 59 42 4f 41 52 44 4c 4c } //WHKEYBOARDLL  1
		$a_80_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //SetWindowsHookEx  1
		$a_80_5 = {6c 6f 67 67 65 72 44 61 74 61 } //loggerData  1
		$a_80_6 = {4b 65 79 6c 6f 67 67 65 72 } //Keylogger  1
		$a_80_7 = {41 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //AntiSandboxie  1
		$a_80_8 = {41 6e 74 69 56 4d 77 61 72 65 } //AntiVMware  1
		$a_80_9 = {53 70 72 65 61 64 55 73 62 } //SpreadUsb  1
		$a_80_10 = {53 63 72 65 65 6e 73 68 6f 74 } //Screenshot  1
		$a_80_11 = {42 6f 74 4b 69 6c 6c 65 72 } //BotKiller  1
	condition:
		((#a_80_0  & 1)*20+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=25
 
}