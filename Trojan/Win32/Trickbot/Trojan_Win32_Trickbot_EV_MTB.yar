
rule Trojan_Win32_Trickbot_EV_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 02 2b d0 03 d3 88 0c 32 8b 2d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b cd 0f af cd 8b d1 0f af 0d ?? ?? ?? ?? 2b d0 0f af d5 8d 04 42 2b 05 ?? ?? ?? ?? 03 44 24 10 8b 54 24 20 03 c2 0f b6 14 37 89 44 24 14 0f b6 04 33 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 14 41 0f af cd 8b 2d ?? ?? ?? ?? 2b d1 03 d5 8a 0c 32 8a 10 32 d1 8b 4c 24 24 88 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}