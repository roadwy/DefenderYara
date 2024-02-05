
rule Trojan_Win32_Hancitor_GA_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {02 cb 80 e9 90 01 01 66 0f b6 c1 66 03 c6 66 05 90 01 02 0f b7 d8 8b 07 05 90 01 04 89 07 a3 90 01 04 b2 90 01 01 8a c3 f6 ea 8a 15 90 01 04 f6 da 2a d0 02 ca 83 c7 04 83 6c 24 90 01 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Hancitor_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 c0 2b d3 8b da 1b c7 8b f8 90 02 19 05 a8 31 04 01 a3 90 02 04 83 c6 90 01 01 89 02 8a 44 24 90 01 01 2a 44 24 90 01 01 2a c3 2c 90 01 01 02 c8 8b c2 83 c0 04 83 6c 24 90 01 01 01 89 44 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}