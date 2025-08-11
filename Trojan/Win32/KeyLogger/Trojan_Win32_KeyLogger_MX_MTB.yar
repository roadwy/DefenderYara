
rule Trojan_Win32_KeyLogger_MX_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.MX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 6c 6f 67 67 65 72 } //1 Keylogger
		$a_01_1 = {50 72 6f 6a 65 63 74 4c 6f 67 66 75 63 6b 2e 70 64 62 } //1 ProjectLogfuck.pdb
		$a_01_2 = {77 00 65 00 62 00 68 00 6f 00 6f 00 6b 00 } //1 webhook
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}