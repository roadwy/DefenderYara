
rule Trojan_Win32_SmokeLoader_GFM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 89 7d ?? e8 ?? ?? ?? ?? 8b 45 ?? 01 45 ?? 33 d2 89 55 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? ?? 01 45 ?? 8b 45 ?? 89 45 ?? 8b 4d ?? 8b c7 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}