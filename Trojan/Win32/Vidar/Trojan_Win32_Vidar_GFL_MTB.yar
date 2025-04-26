
rule Trojan_Win32_Vidar_GFL_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 89 85 ?? ?? ?? ?? 8a 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 84 c9 66 8b 8d ?? ?? ?? ?? 0f 94 c2 f7 d0 33 d0 0f bf c1 03 d0 f7 da 1b d2 42 89 95 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}