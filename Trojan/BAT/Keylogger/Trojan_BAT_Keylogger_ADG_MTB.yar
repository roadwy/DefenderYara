
rule Trojan_BAT_Keylogger_ADG_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {1f 0a 28 14 00 00 0a 00 16 13 06 2b 54 00 11 06 28 ?? ?? ?? 06 13 07 11 07 17 2e 0b 11 07 20 01 80 ff ff fe } //10
		$a_80_1 = {53 61 76 65 64 20 6b 65 79 73 20 66 72 6f 6d } //Saved keys from  3
		$a_80_2 = {4b 65 79 73 74 72 6f 6b 65 73 20 73 61 76 65 64 20 66 72 6f 6d 20 75 73 65 72 } //Keystrokes saved from user  3
		$a_80_3 = {53 6d 74 70 43 6c 69 65 6e 74 } //SmtpClient  3
		$a_80_4 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //GetAsyncKeyState  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}
rule Trojan_BAT_Keylogger_ADG_MTB_2{
	meta:
		description = "Trojan:BAT/Keylogger.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 10 00 09 00 00 "
		
	strings :
		$a_80_0 = {61 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //antiSandboxie  4
		$a_80_1 = {41 64 64 54 6f 41 75 74 6f 72 75 6e } //AddToAutorun  4
		$a_80_2 = {41 6e 74 69 56 69 72 74 75 61 6c 42 6f 78 } //AntiVirtualBox  4
		$a_80_3 = {41 6e 74 69 56 6d 57 61 72 65 } //AntiVmWare  4
		$a_80_4 = {41 6e 74 69 57 69 72 65 53 68 61 72 6b } //AntiWireShark  4
		$a_80_5 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //GetAsyncKeyState  3
		$a_80_6 = {67 65 74 44 65 76 69 63 65 73 } //getDevices  3
		$a_80_7 = {43 41 50 53 4c 4f 43 4b 4f 4e } //CAPSLOCKON  3
		$a_80_8 = {4d 6f 75 73 65 45 6e 74 65 72 } //MouseEnter  3
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=16
 
}