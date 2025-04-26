
rule Trojan_Win32_Ursnif_V_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 30 1c 06 46 3b f7 7c 90 09 39 00 8b 0d ?? ?? ?? ?? 69 c9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 0f b7 1d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_V_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 02 89 75 d8 8b 75 ec c1 2d 84 f0 49 00 07 8b 75 d8 2d 7e a9 c5 3e 89 4d dc 8d 4d d0 f7 19 8b 4d dc 2b 02 } //1
		$a_01_1 = {33 55 f4 ff 45 08 8a 4d 08 33 d0 d3 ca 8b 4d ec 89 4d f4 89 16 83 c6 04 4f 75 dc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_V_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c7 8d 04 45 ?? ?? ?? ?? 2b c6 0f b7 d8 8b 6c 24 ?? 8b 44 24 ?? 03 e9 8b 74 24 ?? 8b cf 13 c2 89 2d ?? ?? ?? ?? a3 ?? ?? ?? ?? 69 c3 ?? ?? ?? ?? 8b 16 81 c2 ?? ?? ?? ?? 89 16 89 15 ?? ?? ?? ?? 2b c8 0f b7 d9 8b d3 8d 72 1c 69 c6 ?? ?? ?? ?? 3d ?? ?? ?? ?? 76 0e } //1
		$a_03_1 = {03 c7 0f b7 e8 8b c5 2b c7 05 ?? ?? ?? ?? 0f b7 c8 89 4c 24 ?? 83 7c 24 ?? ?? 0f 83 9e 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}