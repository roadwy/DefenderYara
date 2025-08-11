
rule Trojan_Win32_ClickFix_CCD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {27 00 69 00 65 00 78 00 27 00 } //1 'iex'
		$a_00_3 = {27 00 69 00 77 00 72 00 27 00 } //1 'iwr'
		$a_00_4 = {3b 00 26 00 24 00 } //1 ;&$
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule Trojan_Win32_ClickFix_CCD_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.CCD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2d 00 62 00 78 00 6f 00 72 00 } //1 -bxor
		$a_00_1 = {46 00 6f 00 72 00 45 00 61 00 63 00 68 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //1 ForEach-Object
		$a_00_2 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 FromBase64String
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}