
rule Trojan_Win32_Pikabot_DH_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 8b 90 01 01 f8 90 01 01 6a 00 ff 55 90 00 } //01 00 
		$a_03_1 = {f7 f6 0f b6 54 15 90 01 01 33 ca 8b 85 90 01 02 ff ff 90 09 11 00 0f b6 0c 90 01 01 8b 85 90 01 02 ff ff 33 d2 be 90 00 } //01 00 
		$a_03_2 = {5e 8b e5 5d c3 90 09 0e 00 88 0c 90 01 01 e9 90 01 02 ff ff ff 95 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}