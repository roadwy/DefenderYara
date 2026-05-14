
rule Trojan_Win32_ClickFix_DJI_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DJI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 00 61 00 76 00 53 00 65 00 74 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 } //1 DavSetCookie
		$a_00_1 = {2e 00 69 00 6e 00 2e 00 6e 00 65 00 74 00 40 00 38 00 30 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1 .in.net@80 http://
		$a_00_2 = {2e 00 69 00 6e 00 2e 00 6e 00 65 00 74 00 2f 00 76 00 65 00 72 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 } //1 .in.net/verification.google
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}