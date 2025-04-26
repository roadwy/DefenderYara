
rule Trojan_Win32_Smokeloader_KAG_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e0 ?? 03 45 ?? 03 d1 33 c2 81 3d ?? ?? ?? ?? 03 0b 00 00 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}