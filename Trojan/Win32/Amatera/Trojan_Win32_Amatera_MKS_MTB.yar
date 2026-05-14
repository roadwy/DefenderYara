
rule Trojan_Win32_Amatera_MKS_MTB{
	meta:
		description = "Trojan:Win32/Amatera.MKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 89 4d f0 8b 55 f8 33 55 f0 81 e2 ff 00 00 00 89 55 ec 8b 45 f8 c1 e8 08 89 45 e4 c7 45 e8 ?? ?? ?? ?? 8b 4d ec 8b 55 e8 8b 04 8a 89 45 e0 8b 4d e4 33 4d e0 89 4d f8 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}