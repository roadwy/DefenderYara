
rule Trojan_Win32_Keylogger_PC_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.PC!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 6f 63 6b 5f 4c 61 62 73 5f 4b 65 79 6c 6f 67 67 65 72 5f 76 31 2e 5f 30 } //1 Shock_Labs_Keylogger_v1._0
		$a_01_1 = {5c 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 \log.txt
		$a_01_2 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 4c 00 6f 00 67 00 20 00 66 00 6f 00 72 00 } //1 Keylogger Log for
		$a_01_3 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 smtp.gmail.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}