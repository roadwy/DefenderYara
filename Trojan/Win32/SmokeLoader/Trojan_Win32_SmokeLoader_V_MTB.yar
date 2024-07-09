
rule Trojan_Win32_SmokeLoader_V_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 f0 8b 45 f0 89 45 ec 8b 55 f8 8b 4d f4 d3 ea 03 55 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 c2 81 c7 ?? ?? ?? ?? 2b f0 83 eb ?? 89 45 ?? 89 7d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}