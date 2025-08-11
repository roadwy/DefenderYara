
rule Trojan_Win32_ClickFix_CCM_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {73 00 63 00 72 00 69 00 70 00 74 00 62 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 scriptblock]::create
		$a_00_2 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_3 = {2e 00 70 00 6e 00 67 00 } //1 .png
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}