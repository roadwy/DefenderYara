
rule Trojan_Win64_Qakbot_AM_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 0f b6 04 08 48 63 84 24 90 01 04 33 d2 b9 90 01 04 48 f7 f1 0f b6 44 14 90 01 01 41 8b d0 33 d0 8b 4c 24 90 01 01 0f af 8c 24 90 01 04 8b 84 24 90 01 04 2b c1 8b 4c 24 90 01 01 0f af 8c 24 90 01 04 03 c1 2b 44 24 90 01 01 03 44 24 90 01 01 48 63 c8 48 8b 84 24 90 01 04 88 14 08 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}