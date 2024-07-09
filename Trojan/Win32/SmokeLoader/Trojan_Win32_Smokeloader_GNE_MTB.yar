
rule Trojan_Win32_Smokeloader_GNE_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 03 44 24 ?? 03 cd 33 c1 8d 0c 3b 33 c1 2b f0 8b d6 c1 e2 ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 03 de 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}