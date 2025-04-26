
rule Trojan_Win32_RedlineStealer_XU_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.XU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 ca 89 4c 24 ?? 89 6c 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 5c 24 ?? 81 44 24 ?? ?? ?? ?? ?? ff 4c 24 ?? 89 2d ?? ?? ?? ?? 89 5c 24 ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}