
rule TrojanSpy_Win32_Keylogger_BT{
	meta:
		description = "TrojanSpy:Win32/Keylogger.BT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 4c 6f 67 20 53 65 72 76 69 63 65 20 53 74 61 72 74 2e 2e 2e } //1 KeyLog Service Start...
		$a_03_1 = {4b 65 79 4c 6f 67 [0-05] 25 73 5c 25 73 [0-07] 6d 72 78 79 6b 65 79 2e 6c 6f 67 } //1
		$a_01_2 = {5b 54 41 42 5d } //1 [TAB]
		$a_01_3 = {25 32 2e 32 64 3a 25 32 2e 32 64 3a 25 32 2e 32 64 } //1 %2.2d:%2.2d:%2.2d
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}