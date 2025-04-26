
rule TrojanSpy_Win32_Keylogger_FP{
	meta:
		description = "TrojanSpy:Win32/Keylogger.FP,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 61 74 65 3a 25 75 2f 25 75 2f 25 75 20 25 75 3a 25 75 } //1 Date:%u/%u/%u %u:%u
		$a_01_1 = {2d 43 6c 69 70 62 6f 61 72 64 2d 3e } //1 -Clipboard->
		$a_01_2 = {5d 00 00 6d 73 69 6e 69 74 00 00 53 4f 46 54 57 41 52 45 5c } //1 ]洀楳楮t匀䙏坔剁居
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}