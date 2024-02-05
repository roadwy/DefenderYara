
rule Trojan_Win32_SpyStealer_XF_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.XF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 44 24 14 8b 44 24 90 01 01 01 44 24 90 01 01 8b f7 c1 e6 90 01 01 03 74 24 90 01 01 33 74 24 90 01 01 81 3d 90 01 08 75 09 55 55 55 ff 15 90 01 04 33 74 24 90 01 01 89 2d 90 01 04 89 74 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 ff 4c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}