
rule Trojan_Win32_Zbot_SPD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 83 c2 04 89 55 f8 8b 45 f8 3b 45 f0 73 38 8b 0d ?? ?? ?? ?? 03 4d f8 8b 11 03 55 f8 a1 ?? ?? ?? ?? 03 45 f8 89 10 8b 4d f8 81 c1 e9 03 00 00 8b 15 ?? ?? ?? ?? 03 55 f8 33 0a a1 ?? ?? ?? ?? 03 45 f8 89 08 eb b7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}