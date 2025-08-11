
rule Trojan_Win32_ClickFix_AAF_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.AAF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 72 00 65 00 73 00 74 00 6d 00 65 00 74 00 68 00 6f 00 64 00 20 00 2d 00 75 00 72 00 69 00 20 00 24 00 [0-3c] 3b 00 20 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 24 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}