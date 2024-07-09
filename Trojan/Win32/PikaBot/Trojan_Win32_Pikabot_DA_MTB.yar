
rule Trojan_Win32_Pikabot_DA_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 fc 88 08 eb ?? eb ?? 99 f7 7d ?? eb ?? 51 bb ?? ?? ?? ?? eb ?? 33 c8 8b 45 ?? eb ?? 0f b6 08 8b 45 ?? eb ?? 55 8b ec eb ?? 8b 45 ?? 0f b6 04 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}