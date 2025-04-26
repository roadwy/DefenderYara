
rule Trojan_Win32_Keylogger_ARA_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_03_0 = {80 c2 41 88 54 ?? ?? ?? 3b ?? 7c e8 } //2
		$a_03_1 = {8a 44 14 14 30 ?? ?? ?? ?? ?? ?? 3b ?? 7c e9 } //3
		$a_03_2 = {8a 44 14 10 30 ?? ?? ?? ?? ?? ?? 3b ?? 7c e9 } //3
		$a_01_3 = {2f 63 32 2f 64 61 74 61 } //2 /c2/data
		$a_01_4 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //2 GetAsyncKeyState
		$a_01_5 = {76 6d 77 61 72 65 2e 65 78 65 } //2 vmware.exe
		$a_01_6 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //2 HttpSendRequestA
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3+(#a_03_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=13
 
}