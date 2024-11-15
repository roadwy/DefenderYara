
rule Trojan_Win32_ParallaxRAT_B_MTB{
	meta:
		description = "Trojan:Win32/ParallaxRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f0 83 c2 ?? 89 55 f0 83 7d f0 ?? ?? ?? 8b 45 fc 33 45 f8 ?? ?? 8b 4d fc d1 ?? 81 f1 ?? ?? ?? ?? 89 4d fc ?? ?? 8b 55 fc d1 ?? 89 55 fc 8b 45 f8 d1 e0 89 45 f8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}