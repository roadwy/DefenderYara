
rule Trojan_Win32_ClickFix_AAD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.AAD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {2e 00 6d 00 73 00 69 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 71 00 6e 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 } //1 .msimsiexec /qn /i http
	condition:
		((#a_00_0  & 1)*1) >=1
 
}