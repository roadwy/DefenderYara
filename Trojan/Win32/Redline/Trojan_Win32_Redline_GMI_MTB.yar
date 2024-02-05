
rule Trojan_Win32_Redline_GMI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 f4 8a 02 88 45 fe 0f b6 4d fe 8b 45 f4 33 d2 f7 75 10 0f b6 92 90 01 04 33 ca 88 4d ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GMI_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 de 33 d8 2b fb 8b d7 c1 e2 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 81 3d 90 01 08 8d 1c 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}