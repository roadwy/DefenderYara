
rule Trojan_Win32_Pikabot_YW_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.YW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e4 0f b6 08 90 13 8b 45 e4 33 d2 90 13 bb 90 01 04 83 c3 90 01 01 90 13 83 c3 90 01 01 53 90 13 5e f7 f6 90 13 8b 45 f8 0f b6 44 10 90 01 01 90 13 33 c8 8b 45 dc 90 13 03 45 e4 88 08 90 13 8b 45 e4 40 90 13 89 45 e4 8b 45 e4 90 13 3b 45 90 01 01 73 90 01 01 8b 45 dc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}