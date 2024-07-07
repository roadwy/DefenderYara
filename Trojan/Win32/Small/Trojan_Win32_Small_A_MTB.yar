
rule Trojan_Win32_Small_A_MTB{
	meta:
		description = "Trojan:Win32/Small.A!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 61 73 73 77 6f 72 64 20 43 72 61 63 6b 65 72 2e 65 78 65 } //1 Password Cracker.exe
		$a_01_1 = {48 6f 74 6d 61 69 6c 20 48 61 63 6b 65 72 2e 65 78 65 } //1 Hotmail Hacker.exe
		$a_01_2 = {4e 65 74 42 49 4f 53 20 48 61 63 6b 65 72 2e 65 78 65 } //1 NetBIOS Hacker.exe
		$a_01_3 = {49 43 51 20 48 61 63 6b 65 72 2e 65 78 65 } //1 ICQ Hacker.exe
		$a_01_4 = {57 65 62 73 69 74 65 20 48 61 63 6b 65 72 2e 65 78 65 } //1 Website Hacker.exe
		$a_01_5 = {4b 65 79 6c 6f 67 67 65 72 2e 65 78 65 } //1 Keylogger.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}