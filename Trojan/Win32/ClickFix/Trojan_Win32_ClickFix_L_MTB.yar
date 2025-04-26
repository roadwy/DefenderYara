
rule Trojan_Win32_ClickFix_L_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.L!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_1 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_2 = {63 00 61 00 70 00 74 00 63 00 68 00 61 00 } //1 captcha
		$a_00_3 = {76 00 65 00 72 00 69 00 66 00 } //1 verif
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}