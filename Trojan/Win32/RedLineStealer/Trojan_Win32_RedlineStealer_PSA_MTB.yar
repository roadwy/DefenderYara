
rule Trojan_Win32_RedlineStealer_PSA_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.PSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 0d ?? ?? ?? ?? ff c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 e4 01 45 0c 8b 45 0c 33 45 f8 33 c8 89 4d ec 8b 45 ec } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_RedlineStealer_PSA_MTB_2{
	meta:
		description = "Trojan:Win32/RedlineStealer.PSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 05 03 55 e8 c1 e0 04 03 45 e4 89 4d f8 33 d0 33 d1 89 55 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 c7 89 45 f4 8b 45 08 03 45 f0 89 45 f8 8b 45 08 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}