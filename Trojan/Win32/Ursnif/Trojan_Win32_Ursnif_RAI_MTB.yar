
rule Trojan_Win32_Ursnif_RAI_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 c5 dc a3 ed 01 8d 1c b9 8b 7c 24 10 89 2f 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 75 } //1
		$a_02_1 = {8b 54 24 10 8d 4c 18 bc 81 c5 bc 67 dd 01 4b 89 2a 0f af d9 66 39 35 ?? ?? ?? ?? 72 } //1
		$a_02_2 = {8b 54 24 10 8b 44 24 14 81 c7 fc c1 fd 01 89 3d ?? ?? ?? ?? 89 bc 28 ?? ?? ?? ?? 0f b7 c2 39 05 ?? ?? ?? ?? 77 } //1
		$a_02_3 = {83 44 24 10 04 8d 91 ?? ?? ?? ?? 0f b6 c0 8b da 2b d8 81 c7 d4 3e 6a 01 83 c3 57 81 7c 24 10 fb 05 00 00 89 7d 00 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}