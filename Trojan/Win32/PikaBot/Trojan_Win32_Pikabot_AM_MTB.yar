
rule Trojan_Win32_Pikabot_AM_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 0a 8b 85 90 01 04 33 d2 be 90 01 04 f7 f6 0f b6 54 15 90 01 01 33 ca 8b 85 90 01 04 0f af 85 90 01 04 0f af 85 90 01 04 8b 95 90 01 04 2b d0 8b 85 90 01 04 0f af 85 90 01 04 0f af 85 90 01 04 2b d0 8b 85 90 01 04 0f af 85 90 01 04 0f af 85 90 01 04 2b d0 8b 85 90 01 04 88 0c 10 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}