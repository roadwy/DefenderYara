
rule Trojan_Win32_Smokeloader_AIN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 c1 ea 05 89 55 f8 8b 45 e0 01 45 f8 8b 45 e8 8b 4d ec c1 e7 04 03 7d d8 03 c8 33 f9 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}