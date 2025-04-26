
rule Trojan_Win32_RedlineStealer_UG_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.UG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 00 0f be d8 c7 44 24 ?? ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f af d8 89 d9 8b 55 ?? 8b 45 ?? 01 d0 0f b6 00 89 c2 89 c8 89 d1 31 c1 8b 55 ?? 8b 45 ?? 01 d0 89 ca 88 10 83 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}