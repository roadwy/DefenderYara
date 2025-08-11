
rule Trojan_Win32_ClickFix_BBBZ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBBZ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-3c] 24 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}