
rule Trojan_Win32_Smokeloader_GZX_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 8b c7 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 55 ?? 8d 04 3e 33 d0 81 3d ?? ?? ?? ?? 03 0b 00 00 89 55 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}