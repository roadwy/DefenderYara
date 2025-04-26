
rule Trojan_Win32_Gozi_GK_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c8 66 89 4d ?? 8b 45 ?? 2d ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b c1 89 45 ?? 8b 45 ?? 83 e8 ?? 0f b7 4d ?? 2b c1 66 89 45 ?? 6b 45 ?? ?? 2b 45 ?? a2 ?? ?? ?? ?? ff 55 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GK_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c8 8b 44 24 [0-01] 83 c0 d3 03 c1 89 44 24 [0-01] 8b f0 a3 [0-04] 8b 44 24 [0-01] 8a cb 2a 4c 24 [0-01] 81 c7 [0-04] 83 44 24 [0-01] 04 80 c1 [0-01] 89 3d [0-04] 89 38 0f b6 c1 66 0f af c3 66 03 c2 ff 4c 24 [0-01] 8b 54 24 [0-01] 0f b7 d8 89 5c 24 [0-01] 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}