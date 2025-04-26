
rule Trojan_Win32_Redline_GJX_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 2f a4 80 2f 67 47 e2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GJX_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 07 67 47 e2 } //10
		$a_03_1 = {f7 d1 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? 33 95 ?? ?? ?? ?? 88 95 ?? ?? ?? ?? 8b 85 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Redline_GJX_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b ca 88 4d ?? 0f b6 45 ?? 03 45 ?? 88 45 ?? 0f b6 4d ?? f7 d1 88 4d ?? 0f b6 55 ?? 33 55 ?? 88 55 ?? 8b 45 ?? 8a 4d ?? 88 4c 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}