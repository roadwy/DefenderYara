
rule Trojan_Win32_Zbot_SIBB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 e8 05 89 44 35 ?? 57 8d 45 ?? 50 ff 75 ?? c6 44 35 ?? ?? 8b 35 ?? ?? ?? ?? 6a ff ff d6 85 c0 74 ?? 8b 4d ?? 8b 55 ?? 2b d9 83 eb 05 c6 45 ?? ?? 89 5d ?? e8 ?? ?? ?? ?? 6a 00 6a 05 8d 45 ?? 50 51 6a ff ff d6 85 c0 } //10
		$a_02_1 = {8b 70 3c 8d b4 06 80 00 00 00 57 8b 3e 8b d8 85 ff 74 ?? 83 7e 04 14 76 ?? 8d 34 07 eb ?? 8d 3c 18 8b 46 10 03 c3 eb ?? 3b 08 75 ?? 89 10 83 c7 04 83 c0 04 83 3f 00 75 ?? 83 c6 14 8b 06 85 c0 75 ?? 33 f6 39 8e ?? ?? ?? ?? 75 ?? 89 96 ?? ?? ?? ?? 83 c6 04 83 fe 18 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}