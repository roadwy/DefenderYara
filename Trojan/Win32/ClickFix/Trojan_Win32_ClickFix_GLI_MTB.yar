
rule Trojan_Win32_ClickFix_GLI_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GLI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {27 00 69 00 27 00 2c 00 27 00 65 00 27 00 2c 00 27 00 78 00 27 00 } //1 'i','e','x'
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}