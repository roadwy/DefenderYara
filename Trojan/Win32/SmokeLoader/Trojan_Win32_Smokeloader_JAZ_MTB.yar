
rule Trojan_Win32_Smokeloader_JAZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.JAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea 05 03 cb 89 55 f8 8b 45 d4 01 45 f8 8b f3 c1 e6 04 03 75 e0 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}