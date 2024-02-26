
rule Trojan_Win32_Pikabot_MB_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 08 8b 85 90 02 04 33 d2 be 90 02 04 f7 f6 0f b6 54 15 a8 33 ca 90 00 } //05 00 
		$a_03_1 = {03 45 fc 2b 85 90 01 04 2b 45 a0 8b 95 90 01 04 88 0c 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}