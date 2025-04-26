
rule Trojan_Win32_SmokeLoader_NL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 75 fc 89 75 f0 8b 45 f0 83 45 f4 ?? 29 45 f4 83 6d f4 ?? 8b 55 f4 c1 e2 ?? 89 55 fc 8b 45 e4 01 45 fc 8b 55 f4 8b 4d f8 8b f2 d3 ee 8d 04 17 31 45 fc 03 75 e0 81 3d ?? ?? ?? ?? ?? ?? 00 00 75 12 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}