
rule Trojan_Win32_Pikabot_DI_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 01 8b 85 90 01 04 33 d2 be 90 01 04 f7 f6 0f b6 54 15 90 01 01 33 ca 90 00 } //0a 00 
		$a_03_1 = {f7 f6 0f b6 54 15 90 01 01 33 ca 90 09 11 00 0f b6 8a 90 01 04 8b 45 90 01 01 33 d2 be 90 00 } //01 00 
		$a_01_2 = {88 0c 02 eb } //01 00 
		$a_01_3 = {88 08 eb c8 } //00 00 
	condition:
		any of ($a_*)
 
}