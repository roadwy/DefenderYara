
rule Trojan_Win32_ClickFix_ZC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,73 00 73 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {68 00 74 00 74 00 70 00 } //5 http
		$a_00_2 = {20 00 69 00 65 00 78 00 } //5  iex
		$a_00_3 = {69 00 77 00 72 00 } //5 iwr
		$a_00_4 = {69 00 72 00 6d 00 } //5 irm
		$a_00_5 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //5 invoke-expression
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5+(#a_00_5  & 1)*5) >=115
 
}
rule Trojan_Win32_ClickFix_ZC_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.ZC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 27 00 23 00 27 00 2c 00 27 00 27 00 29 00 } //1 .replace('#','')
		$a_00_1 = {2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 27 00 40 00 27 00 2c 00 27 00 27 00 29 00 } //1 .replace('@','')
		$a_02_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-01] 30 00 2d 00 77 00 [0-05] 68 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*10) >=11
 
}