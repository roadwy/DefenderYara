
rule Trojan_Win32_Redline_GNE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 07 90 01 01 80 2f 90 01 01 47 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNE_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {88 55 db 0f b6 4d 90 01 01 03 4d dc 88 4d 90 01 01 0f b6 55 90 01 01 c1 fa 90 01 01 0f b6 45 90 01 01 c1 e0 90 01 01 0b d0 88 55 90 01 01 0f b6 4d 90 01 01 03 4d 90 01 01 88 4d 90 01 01 8b 55 90 01 01 8a 45 90 01 01 88 44 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNE_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {f7 d2 88 55 90 01 01 0f b6 45 90 01 01 83 c0 90 01 01 88 45 90 01 01 0f b6 4d 90 01 01 f7 d1 88 4d 90 01 01 0f b6 55 90 01 01 d1 fa 0f b6 45 90 01 01 c1 e0 90 01 01 0b d0 88 55 90 01 01 8b 4d 90 01 01 8a 55 90 01 01 88 54 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}