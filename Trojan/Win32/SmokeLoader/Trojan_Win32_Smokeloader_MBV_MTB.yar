
rule Trojan_Win32_Smokeloader_MBV_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 1a 89 45 fc 8b 45 ?? 01 45 fc 8b d3 c1 e2 04 03 55 e0 33 55 fc 33 d1 2b fa 89 7d ?? 8b 45 d8 29 45 f8 83 6d ec 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}