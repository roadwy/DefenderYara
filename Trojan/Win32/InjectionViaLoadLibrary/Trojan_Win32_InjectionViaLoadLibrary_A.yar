
rule Trojan_Win32_InjectionViaLoadLibrary_A{
	meta:
		description = "Trojan:Win32/InjectionViaLoadLibrary.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 00 69 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 5f 00 31 00 5f 00 78 00 36 00 34 00 2e 00 65 00 78 00 65 00 20 00 73 00 6c 00 65 00 65 00 70 00 69 00 6e 00 67 00 5f 00 62 00 69 00 6e 00 61 00 72 00 79 00 5f 00 78 00 36 00 34 00 2e 00 65 00 78 00 65 00 [0-b0] 5c 00 69 00 6e 00 6a 00 65 00 63 00 74 00 61 00 62 00 6c 00 65 00 5f 00 64 00 6c 00 6c 00 5f 00 78 00 36 00 34 00 2e 00 64 00 6c 00 6c 00 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}