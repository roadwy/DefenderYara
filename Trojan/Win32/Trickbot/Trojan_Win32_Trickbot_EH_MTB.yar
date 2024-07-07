
rule Trojan_Win32_Trickbot_EH_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af d5 0f af d8 0f af d5 2b da 33 d2 8a 14 0f 83 eb 02 0f af d8 33 c0 8a 04 0e 03 c2 33 d2 f7 35 90 01 04 8b 44 24 90 01 01 03 da 2b dd 8b 2d 90 01 04 03 dd 8a 14 0b 8a 18 32 da 8b 54 24 90 01 01 88 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_EH_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e1 06 2b c1 89 45 90 01 01 8b 55 90 01 01 8b 45 90 01 01 03 42 90 01 01 8b 0d 90 01 04 69 c9 f8 00 00 00 2b c1 8b 15 90 01 04 69 d2 f8 00 00 00 2b c2 8b 0d 90 01 04 69 c9 f8 00 00 00 03 c1 89 45 90 01 01 8b 55 90 01 01 8b 42 90 01 01 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 2b c1 89 45 f0 8b 55 90 01 01 03 55 90 01 06 6b c0 28 03 d0 8b 0d 90 01 04 0f af 0d 90 01 04 6b c9 28 2b d1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}