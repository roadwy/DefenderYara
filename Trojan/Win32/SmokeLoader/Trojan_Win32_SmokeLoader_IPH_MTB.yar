
rule Trojan_Win32_SmokeLoader_IPH_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.IPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e1 04 03 4d d8 89 4d f8 8b 0d } //1
		$a_03_1 = {8b c2 d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 c7 31 45 f8 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 81 c3 ?? ?? ?? ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}