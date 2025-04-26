
rule Trojan_Win32_ClickFix_F_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.F!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {7c 00 20 00 69 00 65 00 78 00 } //1 | iex
		$a_00_2 = {72 00 65 00 63 00 61 00 70 00 74 00 63 00 68 00 61 00 } //1 recaptcha
		$a_00_3 = {76 00 65 00 72 00 69 00 66 00 } //1 verif
		$a_00_4 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule Trojan_Win32_ClickFix_F_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.F!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 } //1 mshta http
		$a_00_1 = {2e 00 68 00 74 00 6d 00 6c 00 20 00 23 00 } //1 .html #
		$a_00_2 = {27 00 27 00 5c 00 31 00 } //1 ''\1
		$a_00_3 = {56 00 65 00 72 00 69 00 66 00 79 00 } //1 Verify
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}