
rule Trojan_Win32_Pikabot_HT_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.HT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d1 03 c2 0f b6 c0 89 45 90 01 01 8a 84 05 90 01 04 88 84 3d 90 01 04 8b 45 90 01 01 88 8c 05 90 01 04 0f b6 84 3d 90 01 04 03 c2 0f b6 c0 8a 84 05 90 01 04 32 44 35 90 01 01 88 84 35 90 01 04 46 83 fe 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}