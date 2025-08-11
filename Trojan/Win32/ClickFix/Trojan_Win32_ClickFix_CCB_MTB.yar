
rule Trojan_Win32_ClickFix_CCB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.CCB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {27 00 29 00 2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 [0-10] 23 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}