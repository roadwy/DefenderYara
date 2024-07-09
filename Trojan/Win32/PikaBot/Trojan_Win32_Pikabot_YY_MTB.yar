
rule Trojan_Win32_Pikabot_YY_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e4 0f b6 08 90 13 8b 45 e4 33 d2 90 13 bb ?? ?? ?? ?? 83 c3 ?? 90 13 53 5e 90 13 f7 f6 8b 45 f8 [0-10] 0f b6 44 ?? ?? 33 c8 90 13 8b 45 dc 03 45 e4 90 13 88 08 90 13 8b 45 e4 40 90 13 89 45 e4 8b 45 e4 90 13 3b 45 b0 73 ?? 8b 45 dc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}