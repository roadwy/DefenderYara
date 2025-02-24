
rule Trojan_Win32_Smokeloader_WXD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.WXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 c1 e2 04 03 55 ?? 33 55 ?? 33 d1 89 55 ?? 8b 45 ?? 29 45 f4 8b 45 e8 29 45 f8 83 6d ?? 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}