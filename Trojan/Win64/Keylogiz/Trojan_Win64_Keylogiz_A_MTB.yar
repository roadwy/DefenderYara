
rule Trojan_Win64_Keylogiz_A_MTB{
	meta:
		description = "Trojan:Win64/Keylogiz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //1 GetSystemInfo
		$a_81_1 = {2e 47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 .GetAsyncKeyState
		$a_81_2 = {2e 47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 .GetKeyboardState
		$a_81_3 = {4b 65 79 6c 6f 67 67 65 72 2d 6d 61 69 6e 2f 6d 61 69 6e 2e 67 6f } //1 Keylogger-main/main.go
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}