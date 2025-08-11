
rule Trojan_Win32_SuspProxyExecution_C{
	meta:
		description = "Trojan:Win32/SuspProxyExecution.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {26 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 63 6f 6e 74 72 6f 6c 2e 65 78 65 } //& powershell.exe control.exe  1
		$a_02_1 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-8f] 2e 00 63 00 70 00 6c 00 20 00 26 00 } //1
		$a_02_2 = {5c 74 65 6d 70 5c [0-8f] 2e 63 70 6c 20 26 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}