
rule Trojan_Win64_TrickBotCrypt_EN_MTB{
	meta:
		description = "Trojan:Win64/TrickBotCrypt.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {42 0f b6 04 00 88 04 11 8b 05 90 01 04 0f af 05 90 01 04 8b 54 24 30 03 d0 03 15 90 01 04 03 15 90 01 04 8b 05 90 01 04 0f af 05 90 01 04 8b 0d 90 01 04 03 ca 03 c1 2b 05 90 01 04 03 05 90 01 04 2b 05 90 01 04 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 2b c1 2b 05 90 01 04 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 03 c1 48 63 d0 48 8b 4c 24 50 0f b6 44 24 24 88 04 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}