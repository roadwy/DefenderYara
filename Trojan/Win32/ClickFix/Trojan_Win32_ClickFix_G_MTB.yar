
rule Trojan_Win32_ClickFix_G_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.G!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {2e 00 6d 00 70 00 34 00 3f 00 } //1 .mp4?
		$a_00_3 = {76 00 65 00 72 00 69 00 66 00 } //1 verif
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}