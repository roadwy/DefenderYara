
rule Trojan_Win64_VulDriveLoader_SA_MTB{
	meta:
		description = "Trojan:Win64/VulDriveLoader.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 ff c0 48 89 45 ?? 48 8b 45 ?? 48 39 45 ?? 73 ?? 48 8b 85 ?? ?? ?? ?? 48 8b 4d ?? 0f b7 04 48 0f b7 8d ?? ?? ?? ?? 33 c1 48 8b 4d ?? 48 8b 55 ?? 66 89 04 51 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}