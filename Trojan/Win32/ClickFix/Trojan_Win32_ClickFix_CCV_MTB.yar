
rule Trojan_Win32_ClickFix_CCV_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCV!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3b 00 69 00 65 00 78 00 20 00 28 00 69 00 77 00 72 00 20 00 24 00 } //1 ;iex (iwr $
		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}