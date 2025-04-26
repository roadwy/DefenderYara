
rule Trojan_Win32_Smokeloader_ZAT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.ZAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 c1 ea 05 03 cf 89 55 ?? 8b 45 e0 01 45 ?? c1 e7 04 03 7d dc 33 f9 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}