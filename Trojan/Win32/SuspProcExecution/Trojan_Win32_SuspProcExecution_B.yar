
rule Trojan_Win32_SuspProcExecution_B{
	meta:
		description = "Trojan:Win32/SuspProcExecution.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {72 00 65 00 67 00 [0-08] 61 00 64 00 64 00 20 00 } //1
		$a_00_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4e 00 65 00 74 00 53 00 68 00 20 00 2f 00 76 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 68 00 65 00 6c 00 70 00 65 00 72 00 } //1 \Microsoft\NetSh /v attackiq_helper
		$a_00_2 = {61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 6e 00 65 00 74 00 73 00 68 00 5c 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 68 00 65 00 6c 00 70 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //1 attackiq_netsh\attackiq_helper.dll
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}