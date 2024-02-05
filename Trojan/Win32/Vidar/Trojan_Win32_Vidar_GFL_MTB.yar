
rule Trojan_Win32_Vidar_GFL_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d2 89 85 90 01 04 8a 8d 90 01 04 8b 85 90 01 04 84 c9 66 8b 8d 90 01 04 0f 94 c2 f7 d0 33 d0 0f bf c1 03 d0 f7 da 1b d2 42 89 95 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}