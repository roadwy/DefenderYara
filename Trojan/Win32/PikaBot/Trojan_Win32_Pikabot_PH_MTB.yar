
rule Trojan_Win32_Pikabot_PH_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f6 b8 01 00 00 00 6b c0 00 0f be 84 05 90 01 04 6b c0 90 01 01 be 90 01 01 00 00 00 6b f6 90 01 01 0f be b4 35 90 01 04 0f af c6 2b d0 0f b6 54 15 90 01 01 33 ca 8b 45 90 01 01 03 45 90 01 01 88 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}