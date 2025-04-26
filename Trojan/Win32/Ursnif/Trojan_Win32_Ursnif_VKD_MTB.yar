
rule Trojan_Win32_Ursnif_VKD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.VKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 c2 94 8b c9 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 e0 8b 0d ?? ?? ?? ?? 89 88 67 eb ff ff 90 09 06 00 8b 15 } //2
		$a_02_1 = {8b d7 8b ca b8 ff 01 00 00 03 c1 2d ff 01 00 00 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08 } //2
		$a_00_2 = {0f b6 c1 66 8b ca 66 2b c8 66 83 c1 14 0f b7 f1 8b 4c 24 1c 83 c1 04 89 4c 24 1c 81 f9 f4 0f 00 00 0f 82 } //2
		$a_02_3 = {0f be 04 08 8b 8d ?? ?? ff ff 0f b6 94 0d ?? ?? ff ff 31 c2 88 d3 88 9c 0d ?? ?? ff ff 8b 85 ?? ?? ff ff 83 c0 01 89 85 ?? ?? ff ff e9 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}