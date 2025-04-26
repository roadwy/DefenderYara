
rule Trojan_Win32_Redline_GNC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 50 e8 ?? ?? ?? ?? 83 c4 04 80 34 1f ?? 43 39 de 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNC_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 0f b6 f1 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 8a 84 35 ?? ?? ?? ?? 32 83 ?? ?? ?? ?? 88 83 ?? ?? ?? ?? 43 89 9d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNC_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 10 03 ca 0f b6 45 ?? 03 c8 81 e1 ?? ?? ?? ?? 88 4d ?? 0f b6 4d ?? 03 4d ?? 51 0f b7 55 ?? 03 55 ?? 52 8b 4d ?? e8 ?? ?? ?? ?? 8a 45 ?? 04 ?? 88 45 ?? 0f b6 4d ?? 0f b7 55 ?? 3b ca } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNC_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b d0 88 55 ?? 0f b6 4d ?? 83 c1 ?? 88 4d ?? 0f b6 55 ?? f7 d2 88 55 ?? 0f b6 45 ?? 83 c0 22 88 45 ?? 0f b6 4d ?? f7 d9 88 4d ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 0f b6 45 ?? f7 d8 88 45 ?? 0f b6 4d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}