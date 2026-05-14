
rule Trojan_Win32_SuspClickFix_T{
	meta:
		description = "Trojan:Win32/SuspClickFix.T,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_02_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 [0-02] 5c 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 5c 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}