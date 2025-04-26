
rule Trojan_Win32_SmokeLoader_GBH_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e0 8b 4d ?? 03 45 ?? 89 45 ?? 8b 45 ?? 03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}