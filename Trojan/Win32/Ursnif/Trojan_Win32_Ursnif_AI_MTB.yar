
rule Trojan_Win32_Ursnif_AI_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_02_0 = {8b 09 89 4c 24 10 8b ca f7 d9 2b c8 8b 44 24 1c 03 c1 89 44 24 1c 81 ff ?? ?? ?? ?? 75 } //1
		$a_02_1 = {8d 46 2a 03 c2 8a cb 2a 0d ?? ?? ?? ?? 03 f8 8b 45 00 80 e9 08 88 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 75 ?? 83 7c 24 1c 00 75 } //1
		$a_02_2 = {8b 54 24 14 8b 12 0f b7 f3 8b fe 6b ff ?? 89 15 ?? ?? ?? ?? 8b d6 2b 15 ?? ?? ?? ?? 8d 04 0f 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 0f 85 ?? 00 00 00 } //1
		$a_02_3 = {8b 4c 24 10 2b d7 81 c1 ?? ?? ?? ?? 6a ?? 89 4c 24 14 8d 42 06 89 0d ?? ?? ?? 00 8b 54 24 1c 89 44 24 20 89 0a 0f b7 0d ?? ?? ?? 00 } //1
		$a_02_4 = {2b da 83 eb 08 89 1d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 45 00 8b c2 6b c0 ?? 2b c6 03 c7 6b c0 ?? 2b c2 05 ?? ?? ?? ?? 39 15 ?? ?? ?? ?? 73 } //1
		$a_02_5 = {8d 44 3a c3 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 54 24 14 05 ?? ?? ?? ?? 2b f5 89 02 a3 ?? ?? ?? ?? 83 c2 04 ff 4c 24 18 8d 46 cd a3 ?? ?? ?? ?? 89 54 24 14 0f 85 ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=2
 
}