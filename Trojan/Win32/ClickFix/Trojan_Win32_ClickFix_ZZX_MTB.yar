
rule Trojan_Win32_ClickFix_ZZX_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ZZX!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 24 00 } //1 wscript $
		$a_00_1 = {24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 } //1 $env:temp
		$a_00_2 = {64 00 65 00 6c 00 20 00 24 00 } //1 del $
		$a_00_3 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}