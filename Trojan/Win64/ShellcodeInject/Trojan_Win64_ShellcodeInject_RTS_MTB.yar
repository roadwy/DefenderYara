
rule Trojan_Win64_ShellcodeInject_RTS_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.RTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } //1 Shell_TrayWnd
		$a_01_1 = {53 65 74 57 69 6e 64 6f 77 4c 6f 6e 67 50 74 72 20 66 61 69 6c 65 64 21 } //1 SetWindowLongPtr failed!
		$a_01_2 = {70 61 79 6c 6f 61 64 2e 65 78 65 5f 78 36 34 2e 62 69 6e } //1 payload.exe_x64.bin
		$a_01_3 = {69 6e 76 61 6c 69 64 20 70 61 79 6c 6f 61 64 } //1 invalid payload
		$a_01_4 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 69 73 20 72 75 6e 6e 69 6e 67 20 66 72 6f 6d 3a 20 25 73 } //1 This program is running from: %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}