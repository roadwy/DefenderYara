
rule Trojan_Win32_Gozi_GR_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 d0 83 c0 ?? 0f b7 c0 89 45 ?? 0f b7 c0 2b c7 89 55 ?? 83 c0 ?? a3 ?? ?? ?? ?? 0f b6 c1 03 c0 2b c6 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GR_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 2b c3 fe c1 66 83 c0 ?? 02 c9 66 03 f8 8b 44 24 ?? 2a c8 2a cb 8a c1 c0 e1 ?? 02 c1 8b 4c 24 ?? 02 d0 8b 44 24 ?? 88 15 ?? ?? ?? ?? 85 c0 75 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GR_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2a d9 80 c3 ?? 02 c3 66 0f b6 c8 66 03 ca 8b 16 81 c2 ?? ?? ?? ?? 66 83 c1 ?? 89 16 0f b7 c9 89 15 ?? ?? ?? ?? 8a d1 2a 15 ?? ?? ?? ?? 83 c6 04 80 c2 ?? 02 c2 83 ed 01 8b 15 ?? ?? ?? ?? 75 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GR_MTB_4{
	meta:
		description = "Trojan:Win32/Gozi.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 38 8b 44 24 ?? 2b c3 83 c0 ?? 03 c2 3b 05 [0-04] 90 18 8d 58 a2 81 c7 [0-04] 8b 44 24 ?? 03 de 89 3d [0-04] 33 c9 89 38 83 c0 04 8b 3d [0-04] 89 44 24 ?? 8d 57 ?? 03 d3 ff 4c 24 ?? 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}