
rule Trojan_Win32_Redline_GNS_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 1c 3e 8b c6 f7 74 24 1c 55 55 8a 82 90 01 04 32 c3 fe c8 02 c3 88 04 3e ff 15 90 01 04 28 1c 3e 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNS_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {d1 f9 0f b6 55 90 01 01 c1 e2 90 01 01 0b ca 88 4d 90 01 01 0f b6 45 90 01 01 2d 90 01 04 88 45 90 01 01 0f b6 4d 90 01 01 f7 d9 88 4d 90 01 01 0f b6 55 90 01 01 03 55 90 01 01 88 55 90 01 01 8b 45 90 01 01 8a 4d 90 01 01 88 4c 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}