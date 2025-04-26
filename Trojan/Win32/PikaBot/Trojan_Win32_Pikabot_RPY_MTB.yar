
rule Trojan_Win32_Pikabot_RPY_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 ff 7f 00 00 f7 f7 31 d2 8d 78 01 89 c8 8b 0c 9e f7 f7 01 d8 8d 04 86 8b 10 89 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Pikabot_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Pikabot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 ed 01 86 9c 00 00 00 0f b6 c2 0f b6 56 68 0f af d0 a1 ?? ?? ?? ?? 88 14 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Pikabot_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Pikabot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb 00 00 00 00 21 5d f0 e9 52 02 00 00 e9 e0 02 00 00 bb 03 00 00 00 83 c3 05 eb 07 8b 45 f0 33 d2 eb ef 53 5e eb 14 8b 45 e8 03 45 f0 e9 84 02 00 00 bb 0c 00 00 00 03 e3 eb c5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}