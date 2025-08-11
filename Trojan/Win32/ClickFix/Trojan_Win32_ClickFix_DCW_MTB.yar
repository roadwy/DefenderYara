
rule Trojan_Win32_ClickFix_DCW_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DCW!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffca 00 ffffffca 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {20 00 23 00 20 00 } //100  # 
		$a_00_2 = {69 00 77 00 72 00 } //1 iwr
		$a_00_3 = {7c 00 20 00 69 00 65 00 78 00 } //1 | iex
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=202
 
}