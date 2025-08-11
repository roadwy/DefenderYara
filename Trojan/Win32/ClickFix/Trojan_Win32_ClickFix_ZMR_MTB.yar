
rule Trojan_Win32_ClickFix_ZMR_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZMR!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2d 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00 } //1 -Headers
		$a_00_1 = {2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 .GetString($
		$a_00_2 = {2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 .content
		$a_00_3 = {69 00 65 00 78 00 20 00 24 00 } //1 iex $
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}