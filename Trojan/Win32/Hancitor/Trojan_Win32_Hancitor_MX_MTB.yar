
rule Trojan_Win32_Hancitor_MX_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 14 11 88 10 8b 45 f8 83 c0 01 89 45 f8 } //1
		$a_02_1 = {8b c1 33 d8 8b c3 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 09 06 00 8b 1d 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}