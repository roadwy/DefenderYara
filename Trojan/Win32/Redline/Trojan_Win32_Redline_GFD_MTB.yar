
rule Trojan_Win32_Redline_GFD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8b f2 8b 7d ?? 8b 5d ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0b fa 0b d8 f7 d7 f7 d3 0f bf 05 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 99 33 f8 33 da 2b cf 1b f3 89 4d ?? 89 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}