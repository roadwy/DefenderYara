
rule Trojan_Win32_Redline_GMI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 f4 8a 02 88 45 fe 0f b6 4d fe 8b 45 f4 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GMI_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 de 33 d8 2b fb 8b d7 c1 e2 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8d 1c 2f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}