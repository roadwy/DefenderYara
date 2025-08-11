
rule Trojan_Win32_ClickFix_DAI_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DAI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,36 00 36 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //50 powershell
		$a_00_1 = {2d 00 55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 73 00 69 00 6e 00 67 00 29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 -UseBasicParsing).Content
		$a_00_2 = {69 00 65 00 78 00 } //1 iex
		$a_00_3 = {69 00 77 00 72 00 20 00 24 00 } //1 iwr $
		$a_00_4 = {76 00 65 00 72 00 69 00 66 00 } //1 verif
	condition:
		((#a_00_0  & 1)*50+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=54
 
}