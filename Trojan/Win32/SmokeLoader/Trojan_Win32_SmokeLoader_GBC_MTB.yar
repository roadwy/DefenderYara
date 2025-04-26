
rule Trojan_Win32_SmokeLoader_GBC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e0 8b 4d ?? 8b d6 d3 ea 03 45 ?? 89 45 ?? 8b 45 ?? 03 55 ?? 03 c6 89 45 ?? 8b 45 ?? 31 45 ?? 31 55 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}