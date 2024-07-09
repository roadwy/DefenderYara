
rule Trojan_Win32_RedlineStealer_XK_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.XK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 00 0f be d8 c7 44 24 ?? ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f af d8 89 da 8b 4d ?? 8b 45 ?? 01 c8 8b 5d ?? 8b 4d ?? 01 d9 0f b6 09 31 ca 88 10 83 45 f4 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}