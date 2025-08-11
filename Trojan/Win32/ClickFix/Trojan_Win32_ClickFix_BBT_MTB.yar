
rule Trojan_Win32_ClickFix_BBT_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBT!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {7c 00 25 00 7b 00 24 00 5f 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 |%{$_.Content
		$a_00_1 = {6a 00 6f 00 69 00 6e 00 } //1 join
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}