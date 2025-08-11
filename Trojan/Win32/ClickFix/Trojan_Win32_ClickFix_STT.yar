
rule Trojan_Win32_ClickFix_STT{
	meta:
		description = "Trojan:Win32/ClickFix.STT,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {20 00 23 00 20 00 } //1  # 
		$a_00_1 = {3a 00 2f 00 2f 00 } //1 ://
		$a_00_2 = {27 00 2b 00 27 00 } //1 '+'
		$a_00_3 = {5d 00 3a 00 3a 00 } //1 ]::
		$a_00_4 = {3b 00 26 00 24 00 } //1 ;&$
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}