
rule Trojan_Win32_SuspProxyExecution_A{
	meta:
		description = "Trojan:Win32/SuspProxyExecution.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 61 73 6d 2e 65 78 65 } //regasm.exe  1
		$a_80_1 = {72 65 67 73 76 63 73 2e 65 78 65 } //regsvcs.exe  1
		$a_02_2 = {2f 00 74 00 6c 00 62 00 3a 00 [0-c8] 2e 00 74 00 6c 00 62 00 } //2
		$a_02_3 = {2f 74 6c 62 3a [0-c8] 2e 74 6c 62 } //2
		$a_80_4 = {5f 63 6f 6d 70 6f 6e 65 6e 74 2e 64 6c 6c } //_component.dll  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2+(#a_80_4  & 1)*2) >=5
 
}