
rule Trojan_Win32_Hancitor_WP_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.WP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d1 89 15 90 01 04 a1 90 01 04 05 c8 c8 03 01 a3 90 01 04 8b 0d 90 01 04 03 4d f8 8b 15 90 01 04 89 91 90 01 04 a1 90 01 04 8b 0d 90 01 04 8d 54 01 33 66 90 01 03 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}