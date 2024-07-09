
rule Trojan_Win32_Smokeloader_IK_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.IK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 57 33 c9 bf 7e 07 00 00 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 3b cf 72 ea } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_IK_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.IK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b c6 c1 e0 ?? 03 45 f0 8d 0c 32 33 c1 33 45 ?? 2b f8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}