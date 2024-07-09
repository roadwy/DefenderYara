
rule Trojan_Win32_SmokeLoader_KZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.KZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 8b 4d ?? 8b c6 d3 e0 03 55 ?? 89 7d ?? 89 55 ?? 03 45 ?? 33 c2 33 c7 29 45 ?? ff 4d ?? 89 45 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}