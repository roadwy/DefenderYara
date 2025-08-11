
rule Trojan_Win32_ClickFix_CCF_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2d 00 62 00 78 00 6f 00 72 00 } //1 -bxor
		$a_00_1 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
		$a_00_2 = {66 00 6f 00 72 00 28 00 24 00 } //1 for($
		$a_00_3 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 FromBase64String($
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}