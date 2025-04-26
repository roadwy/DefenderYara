
rule TrojanSpy_Win32_Keylogger_CI{
	meta:
		description = "TrojanSpy:Win32/Keylogger.CI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 4b 65 79 4c 6f 67 67 65 72 } //1 uKeyLogger
		$a_01_1 = {66 75 53 61 6e 64 42 6f 78 } //1 fuSandBox
		$a_01_2 = {75 50 65 72 73 69 73 74 65 6e 63 65 } //1 uPersistence
		$a_01_3 = {5b 2a 43 4c 49 50 42 4f 41 52 44 2a 5d } //1 [*CLIPBOARD*]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}