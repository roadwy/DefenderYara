
rule Trojan_Win32_ClickFix_Y_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.Y!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6d 00 68 00 73 00 74 00 61 00 [0-20] 68 00 74 00 74 00 70 00 [0-50] 23 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}