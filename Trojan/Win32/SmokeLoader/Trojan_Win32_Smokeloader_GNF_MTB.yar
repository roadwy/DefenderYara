
rule Trojan_Win32_Smokeloader_GNF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 8d 4c 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 01 5c 24 ?? 8d 34 17 d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 31 74 24 ?? 81 3d ?? ?? ?? ?? 21 01 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}