
rule Trojan_Win32_Redline_GNS_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 1c 3e 8b c6 f7 74 24 1c 55 55 8a 82 ?? ?? ?? ?? 32 c3 fe c8 02 c3 88 04 3e ff 15 ?? ?? ?? ?? 28 1c 3e 55 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNS_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d1 f9 0f b6 55 ?? c1 e2 ?? 0b ca 88 4d ?? 0f b6 45 ?? 2d ?? ?? ?? ?? 88 45 ?? 0f b6 4d ?? f7 d9 88 4d ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 8b 45 ?? 8a 4d ?? 88 4c 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}