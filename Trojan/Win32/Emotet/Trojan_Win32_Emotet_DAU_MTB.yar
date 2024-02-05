
rule Trojan_Win32_Emotet_DAU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 09 81 c3 90 01 04 0f b6 c9 01 f1 21 d9 8b 75 90 01 01 8a 0c 0e 8b 5d 90 01 01 32 0c 3b 8b 7d 90 01 01 8b 75 90 01 01 29 f7 8b 75 90 01 01 8b 5d 90 01 01 88 0c 1e 90 00 } //01 00 
		$a_02_1 = {01 f9 8b 7d 90 01 01 21 f9 8b 7d 90 01 01 8a 1c 0f 8b 4d 90 01 01 8b 55 90 01 01 32 1c 11 8b 4d 90 01 01 88 1c 11 90 00 } //01 00 
		$a_02_2 = {01 da 21 f2 8a 14 17 8b 75 90 01 01 8b 5d 90 01 01 32 14 1e 8b 75 90 01 01 88 14 1e 90 00 } //01 00 
		$a_02_3 = {01 d1 8b 54 24 90 01 01 21 d1 8b 54 24 90 01 01 8a 0c 0a 8b 54 24 90 01 01 32 0c 32 8b 74 24 90 01 01 88 0c 1e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}