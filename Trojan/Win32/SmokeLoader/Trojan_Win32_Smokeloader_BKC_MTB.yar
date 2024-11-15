
rule Trojan_Win32_Smokeloader_BKC_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.BKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d1 c1 ea 05 89 55 ?? 8b 45 e0 01 45 ?? 8b 45 ec 8b f1 c1 e6 04 03 75 d8 03 c1 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}