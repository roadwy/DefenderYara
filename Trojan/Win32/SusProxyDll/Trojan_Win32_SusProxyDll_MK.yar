
rule Trojan_Win32_SusProxyDll_MK{
	meta:
		description = "Trojan:Win32/SusProxyDll.MK,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 75 6e 64 6c 6c 33 32 } //rundll32  1
		$a_80_1 = {70 68 6f 6e 65 68 6f 6d 65 5f 6d 61 69 6e 20 } //phonehome_main   1
		$a_80_2 = {70 68 6f 6e 65 48 6f 6d 65 } //phoneHome  1
		$a_80_3 = {5c 5c 2e 5c 70 69 70 65 5c 6d 6f 76 65 } //\\.\pipe\move  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}