
rule Trojan_Win32_Hancitor_AC_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 c7 3b c8 74 90 01 01 28 8e 90 01 04 8a da 8a 3d 90 01 04 02 d9 8d 90 01 02 0f b6 c3 8b 90 01 03 2b c8 81 c2 90 01 04 03 d1 8b 90 00 } //01 00 
		$a_03_1 = {0f b6 c7 3b c1 77 90 01 01 8a fb 8a c3 c0 e3 03 02 c3 88 3d 90 01 04 8a da 2a d8 0f b6 d3 2b d1 83 ea 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}