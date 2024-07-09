
rule Trojan_Win32_Predator_PVD_MTB{
	meta:
		description = "Trojan:Win32/Predator.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 81 3d ?? ?? ?? ?? ac 10 00 00 56 a3 ?? ?? ?? ?? 8b f0 75 90 09 05 00 a1 } //2
		$a_02_1 = {69 c0 fd 43 03 00 56 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75 90 09 05 00 a1 } //2
		$a_00_2 = {0f b6 84 15 b4 f8 ff ff 0f b6 c9 03 c8 0f b6 c1 0f b6 84 05 b4 f8 ff ff 30 84 3d bc f9 ff ff } //2
		$a_02_3 = {8b 45 08 03 45 fc 0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 fc 88 18 eb } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}