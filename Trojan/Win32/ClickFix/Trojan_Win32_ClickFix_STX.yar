
rule Trojan_Win32_ClickFix_STX{
	meta:
		description = "Trojan:Win32/ClickFix.STX,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_1 = {20 00 23 00 20 00 } //1  # 
		$a_00_2 = {3a 00 2f 00 2f 00 } //1 ://
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}