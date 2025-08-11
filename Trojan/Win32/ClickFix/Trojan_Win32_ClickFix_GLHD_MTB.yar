
rule Trojan_Win32_ClickFix_GLHD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GLHD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 29 00 29 00 2e 00 54 00 72 00 69 00 6d 00 28 00 29 00 } //1 ).Content)).Trim()
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}