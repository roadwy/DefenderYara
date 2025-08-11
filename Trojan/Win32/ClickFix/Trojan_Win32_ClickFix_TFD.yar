
rule Trojan_Win32_ClickFix_TFD{
	meta:
		description = "Trojan:Win32/ClickFix.TFD,SIGNATURE_TYPE_CMDHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {56 00 65 00 72 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Verification
		$a_00_3 = {7c 00 69 00 65 00 78 00 } //1 |iex
		$a_00_4 = {20 00 69 00 77 00 72 00 20 00 } //1  iwr 
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=14
 
}