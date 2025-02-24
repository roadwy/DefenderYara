
rule Trojan_Win32_ClickFix_O_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.O!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-10] 2d 00 65 00 } //10
		$a_00_1 = {69 00 77 00 72 00 } //1 iwr
		$a_00_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 } //1 invoke-webrequest
		$a_00_3 = {69 00 65 00 78 00 } //1 iex
		$a_00_4 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //1 invoke-expression
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=11
 
}