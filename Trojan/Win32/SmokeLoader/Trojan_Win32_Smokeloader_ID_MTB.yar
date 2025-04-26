
rule Trojan_Win32_Smokeloader_ID_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.ID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e0 ?? 03 45 ?? 33 45 ?? 33 c3 2b f0 8b 45 ?? 01 45 ?? 29 45 ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Smokeloader_ID_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.ID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 8b 4d ?? 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 2b 4d ?? 8d 45 ?? 89 4d ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}