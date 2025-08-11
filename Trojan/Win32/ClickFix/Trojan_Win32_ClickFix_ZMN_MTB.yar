
rule Trojan_Win32_ClickFix_ZMN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZMN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
		$a_00_2 = {5d 00 2b 00 24 00 } //1 ]+$
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}