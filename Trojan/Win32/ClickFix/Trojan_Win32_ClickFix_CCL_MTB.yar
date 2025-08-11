
rule Trojan_Win32_ClickFix_CCL_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {67 00 69 00 20 00 5c 00 57 00 2a 00 5c 00 2a 00 33 00 32 00 5c 00 63 00 3f 00 3f 00 6c 00 2e 00 65 00 } //1 gi \W*\*32\c??l.e
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}