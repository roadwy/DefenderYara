
rule Trojan_Win32_ClickFix_CCC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2b 00 5b 00 63 00 68 00 61 00 72 00 5d 00 } //1 +[char]
		$a_00_1 = {6a 00 6f 00 69 00 6e 00 } //1 join
		$a_00_2 = {2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 .content
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}