
rule Trojan_Win32_Neoreblamy_BP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 75 f8 33 d2 c7 45 fc ?? 00 00 00 8b 4d fc 8b 45 f8 f7 f1 0f af 45 fc 8b 4d f8 2b c8 8b 45 08 ff 34 88 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72 } //10
		$a_03_1 = {0f af d1 03 c2 8b 8d ?? ?? ff ff 03 c8 0f b6 85 ?? ?? ff ff 0f af 85 } //5
		$a_03_2 = {0f af c8 0f b6 45 ?? 0f af d0 0f b6 45 ?? 2b d1 03 d0 } //5
		$a_01_3 = {2b d0 0f b6 45 fc 0f b6 4d fe 0f af d0 0f b6 45 fc 0f af c8 03 d1 } //5
		$a_03_4 = {0f af c8 0f b6 45 ?? 0f af 45 ?? 2b d1 2b d0 03 55 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_01_3  & 1)*5+(#a_03_4  & 1)*5) >=10
 
}