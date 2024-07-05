
rule Trojan_Win32_Redline_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GXZ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {56 55 53 8d 4c 24 90 01 01 e8 90 01 04 8d 4c 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 8d 4c 24 90 01 01 8a 44 04 90 01 01 30 87 90 01 04 e8 90 01 04 8b 5c 24 90 01 01 47 8b 6c 24 90 01 01 81 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}