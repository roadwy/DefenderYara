
rule Trojan_Win32_SpyKeylogger_SE_MTB{
	meta:
		description = "Trojan:Win32/SpyKeylogger.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 01 41 84 c0 75 f9 } //1
		$a_01_1 = {6b 65 79 6c 6f 67 67 65 72 2e 6c 6f 67 } //1 keylogger.log
		$a_01_2 = {4c 6f 67 67 69 6e 67 20 6f 75 74 70 75 74 20 74 6f } //1 Logging output to
		$a_01_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_01_4 = {47 65 74 57 69 6e 64 6f 77 54 65 78 74 41 } //1 GetWindowTextA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}