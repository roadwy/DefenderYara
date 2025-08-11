
rule Trojan_Win32_ClickFix_EED_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.EED!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {56 00 65 00 72 00 69 00 66 00 79 00 20 00 79 00 6f 00 75 00 20 00 61 00 72 00 65 00 20 00 68 00 75 00 6d 00 61 00 6e 00 } //1 Verify you are human
	condition:
		((#a_00_0  & 1)*1) >=1
 
}