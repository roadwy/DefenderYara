
rule Trojan_Win32_Fragtor_ZIN_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ZIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c9 33 ca 89 1d ?? ?? ?? ?? 89 4c 24 54 8b 4c 24 28 d3 e7 89 7c 24 38 8b 7c 24 60 8b 94 24 98 00 00 00 8b 44 24 40 05 69 21 00 00 89 84 24 a8 00 00 00 8b 44 24 5c 0f af 44 24 20 89 44 24 5c 66 a3 ?? ?? ?? ?? 8b 84 24 84 00 00 00 0f b7 c0 39 44 24 38 7d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}