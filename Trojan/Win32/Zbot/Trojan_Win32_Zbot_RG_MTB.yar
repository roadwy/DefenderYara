
rule Trojan_Win32_Zbot_RG_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 b4 25 2c ff ff ff 8c 12 00 00 89 b4 25 ?? ff ff ff 8b 32 89 34 87 c1 2d ?? ?? ?? ?? 07 40 3b 45 14 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zbot_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 03 8b c8 83 c0 08 83 e1 07 89 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 14 2a d3 ea 8b ce 23 d3 8b ea d3 e5 8d 0c 3e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zbot_RG_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 40 00 ff d6 6a 40 68 00 30 00 00 ff b5 70 ff ff ff 6a 00 ff 55 d4 8b d0 33 c0 eb 1f [0-20] 8a 0c 0b 8b b5 74 ff ff ff 32 0c 06 88 0c 02 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}