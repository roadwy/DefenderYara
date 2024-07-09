
rule BrowserModifier_Win32_IGetNet{
	meta:
		description = "BrowserModifier:Win32/IGetNet,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 33 32 32 2e 65 78 65 [0-04] 53 79 73 74 65 6d } //1
		$a_00_1 = {62 68 6f 2e 64 6c 6c 00 62 68 6f 2e 64 6c 5f } //1
		$a_00_2 = {4f 76 65 72 77 72 69 74 69 6e 67 20 48 4f 53 54 53 20 66 69 6c 65 20 27 25 73 27 2e } //1 Overwriting HOSTS file '%s'.
		$a_02_3 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 [0-08] 69 00 47 00 65 00 74 00 4e 00 65 00 74 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}