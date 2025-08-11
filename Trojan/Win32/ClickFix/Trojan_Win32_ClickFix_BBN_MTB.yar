
rule Trojan_Win32_ClickFix_BBN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 27 00 2b 00 27 00 } //1
		$a_00_1 = {29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 29 00 } //1 ).Content)
		$a_00_2 = {27 00 3b 00 20 00 26 00 28 00 24 00 } //1 '; &($
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}