
rule Trojan_Win32_Hancitor_GN_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8d 04 52 03 c0 2b 45 90 01 01 2b 45 90 01 01 03 c2 0f b7 f0 6b c6 90 01 01 89 45 90 01 01 03 c1 0f b7 f8 0f b6 05 90 01 04 83 c0 90 01 01 a3 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Hancitor_GN_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b7 45 fc 99 2b 05 90 01 04 1b 15 90 01 04 33 c9 03 45 90 01 01 13 d1 a3 90 01 04 89 15 90 01 04 0f b6 05 90 01 04 8b 0d 90 01 04 2b c8 03 0d 90 01 04 88 0d 90 01 04 ff 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}