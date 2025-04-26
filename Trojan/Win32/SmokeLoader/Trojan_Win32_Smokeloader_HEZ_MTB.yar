
rule Trojan_Win32_Smokeloader_HEZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 05 89 45 ?? 8b 45 e0 01 45 ?? 8b c1 c1 e0 04 03 45 dc 33 45 f8 33 45 e4 2b d0 89 55 f0 8b 45 d8 29 45 fc ff 4d ec 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}