
rule Trojan_Win32_Redline_GFD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c8 8b f2 8b 7d 90 01 01 8b 5d 90 01 01 8b 15 90 01 04 a1 90 01 04 0b fa 0b d8 f7 d7 f7 d3 0f bf 05 90 01 04 03 85 90 01 04 99 33 f8 33 da 2b cf 1b f3 89 4d 90 01 01 89 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}