
rule Trojan_Win32_ClickFix_TFC{
	meta:
		description = "Trojan:Win32/ClickFix.TFC,SIGNATURE_TYPE_CMDHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_1 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 FromBase64String
		$a_00_2 = {2d 00 62 00 78 00 6f 00 72 00 } //1 -bxor
		$a_00_3 = {69 00 65 00 78 00 28 00 } //1 iex(
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=13
 
}