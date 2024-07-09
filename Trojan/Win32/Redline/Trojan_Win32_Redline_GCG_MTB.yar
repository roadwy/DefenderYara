
rule Trojan_Win32_Redline_GCG_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 89 55 ec 66 8b 45 e8 8b 15 ?? ?? ?? ?? 0f b7 c8 8d 44 11 01 0f b6 0d ?? ?? ?? ?? 33 c1 89 45 f4 8b 45 c0 8b 4d c4 5f } //10
		$a_01_1 = {02 c9 b2 8f 2a d1 2a d3 b9 85 00 00 00 66 33 c1 88 15 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}