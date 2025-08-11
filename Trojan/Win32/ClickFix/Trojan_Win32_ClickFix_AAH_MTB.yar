
rule Trojan_Win32_ClickFix_AAH_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.AAH!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}