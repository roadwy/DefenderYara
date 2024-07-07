
rule Trojan_Win32_Spycos_B{
	meta:
		description = "Trojan:Win32/Spycos.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6a 4b 46 53 48 4d 49 32 45 7a 31 79 56 72 33 41 4a 52 70 53 61 53 34 4b 58 78 67 53 59 55 4c 74 51 4f 57 31 7a 5a 57 4c 4e } //1 cjKFSHMI2Ez1yVr3AJRpSaS4KXxgSYULtQOW1zZWLN
		$a_02_1 = {8d 55 f8 b8 7b 00 00 00 e8 90 01 03 ff 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}