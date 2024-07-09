
rule Trojan_Win32_Smokeloader_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 44 24 ?? 89 2d ?? ?? ?? ?? 33 c1 8b 4c 24 ?? 03 ce 33 c1 2b f8 8b d7 c1 e2 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 89 54 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}