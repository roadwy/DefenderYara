
rule Trojan_Win32_NetshHelper_A{
	meta:
		description = "Trojan:Win32/NetshHelper.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {6e 65 74 73 68 2e 65 78 65 } //netsh.exe  1
		$a_80_1 = {61 64 64 20 68 65 6c 70 65 72 } //add helper  1
		$a_02_2 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-8f] 2e 00 64 00 6c 00 6c 00 } //1
		$a_02_3 = {5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-8f] 2e 64 6c 6c } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}