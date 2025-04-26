
rule Trojan_Win32_Neoreblamy_BAM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 fc 50 e8 ?? ?? ?? ff 59 59 8b 4d ?? 8b 49 04 0f b6 04 01 50 8b 45 ?? 03 45 fc 8b 4d ?? 8b 09 0f b6 04 01 50 e8 ?? ?? ?? ff 59 59 50 8d 4d e4 e8 } //3
		$a_01_1 = {55 8b ec 51 51 8b 45 08 33 d2 f7 75 0c 89 45 fc 8b 45 0c 0f af 45 fc 8b 4d 08 2b c8 89 4d f8 8b 45 f8 } //2
		$a_03_2 = {8b 4d 08 ff 34 81 ff 34 b7 e8 ?? ?? ?? ?? 83 c4 10 89 04 b7 46 3b f3 72 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=5
 
}