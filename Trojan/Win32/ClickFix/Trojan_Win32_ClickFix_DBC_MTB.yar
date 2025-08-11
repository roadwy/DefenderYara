
rule Trojan_Win32_ClickFix_DBC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DBC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_2 = {69 00 72 00 73 00 2e 00 67 00 6f 00 76 00 2d 00 } //10 irs.gov-
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*10) >=11
 
}