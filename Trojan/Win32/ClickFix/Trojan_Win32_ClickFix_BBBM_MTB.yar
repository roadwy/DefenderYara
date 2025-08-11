
rule Trojan_Win32_ClickFix_BBBM_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBBM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {26 00 26 00 20 00 63 00 75 00 72 00 6c 00 20 00 2d 00 6b 00 20 00 2d 00 6f 00 } //1 && curl -k -o
		$a_00_1 = {26 00 26 00 20 00 73 00 74 00 61 00 72 00 74 00 } //1 && start
		$a_00_2 = {26 00 26 00 20 00 65 00 63 00 68 00 6f 00 } //1 && echo
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}