
rule Trojan_Win32_ClickFix_ZZR_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZZR!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {61 00 62 00 63 00 64 00 } //-100 abcd
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*-100) >=2
 
}