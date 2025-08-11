
rule Trojan_Win32_ClickFix_ZI{
	meta:
		description = "Trojan:Win32/ClickFix.ZI,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 70 00 6c 00 61 00 63 00 65 00 } //10 replace
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}