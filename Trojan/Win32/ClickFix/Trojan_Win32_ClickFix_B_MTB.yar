
rule Trojan_Win32_ClickFix_B_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.B!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 } //1 mshta http
		$a_00_1 = {2e 00 68 00 74 00 6d 00 6c 00 20 00 23 00 } //1 .html #
		$a_00_2 = {27 00 27 00 5c 00 31 00 } //1 ''\1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}