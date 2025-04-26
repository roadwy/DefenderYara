
rule Trojan_Win32_Smokeloader_GTN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b f9 c1 e7 ?? 03 7d ?? 8d 04 0b 33 f8 81 3d ?? ?? ?? ?? 03 0b 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}