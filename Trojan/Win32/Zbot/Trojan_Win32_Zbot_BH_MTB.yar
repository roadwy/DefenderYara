
rule Trojan_Win32_Zbot_BH_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b f0 89 35 90 02 04 8b 55 d8 8b 45 e8 33 c2 89 45 d8 8b 5d fc 8b 45 d8 2b d8 89 5d d8 3b f0 0f 85 90 00 } //01 00 
		$a_03_1 = {23 c7 89 05 90 02 04 8b 1d 90 02 04 33 df 89 1d 90 02 04 8b 3d 90 02 04 47 4f 89 3d 90 02 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}