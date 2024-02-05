
rule Trojan_Win32_Emotet_DHZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {47 23 fb 8b 54 b8 08 03 ea 23 eb 8b 5c a8 08 89 5c b8 08 89 54 a8 08 03 da 23 1d 90 01 04 8a 54 98 08 32 16 88 11 90 00 } //01 00 
		$a_00_1 = {8b ea c1 e5 13 c1 ea 0d 0b d5 80 f9 61 0f b6 c9 72 03 83 e9 20 03 d1 8a 48 01 40 84 c9 75 e1 } //01 00 
		$a_02_2 = {8b 55 fc 89 54 98 08 8b 5d f8 03 da 23 1d 90 01 04 8a 54 98 08 32 16 8b 5d 08 88 11 90 00 } //01 00 
		$a_00_3 = {8b f0 c1 e6 13 c1 e8 0d 0b c6 80 f9 61 0f b6 c9 72 03 83 e9 20 03 c1 42 8a 0a 84 c9 75 e2 } //00 00 
	condition:
		any of ($a_*)
 
}