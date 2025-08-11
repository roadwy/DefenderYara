
rule Trojan_Win32_ClickFix_STY{
	meta:
		description = "Trojan:Win32/ClickFix.STY,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-10] 63 00 75 00 72 00 6c 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 } //1
		$a_00_1 = {2e 00 74 00 78 00 74 00 20 00 7c 00 20 00 69 00 65 00 78 00 27 00 23 00 } //1 .txt | iex'#
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}