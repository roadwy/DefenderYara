
rule Trojan_Win32_Redline_CAX_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 44 24 28 56 8d 4c 24 14 89 44 24 18 c7 05 90 02 04 fc 03 cf ff e8 90 02 04 8b 44 24 14 33 44 24 10 c7 05 90 02 04 00 00 00 00 2b f8 8b cf c1 e1 04 81 3d 90 02 04 8c 07 00 00 89 44 24 14 89 4c 24 10 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}