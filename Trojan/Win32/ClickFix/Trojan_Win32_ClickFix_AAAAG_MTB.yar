
rule Trojan_Win32_ClickFix_AAAAG_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.AAAAG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {26 00 26 00 20 00 63 00 75 00 72 00 6c 00 } //1 && curl
		$a_00_1 = {2e 00 6c 00 6f 00 67 00 20 00 26 00 26 00 } //1 .log &&
		$a_00_2 = {26 00 26 00 20 00 66 00 74 00 70 00 } //1 && ftp
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}