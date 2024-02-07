
rule Trojan_Win32_TrickBotCrypt_GM_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 0e 0f b6 c3 03 c7 33 d2 f7 35 90 01 04 8b fa 8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 f7 35 90 01 04 8b 44 24 18 8a 1c 28 8a 14 0a 32 da 88 1c 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBotCrypt_GM_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d1 8b 0d 90 01 04 0f af 0d 90 01 04 2b d1 2b 15 90 01 04 03 15 90 01 04 8b 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2 8b 4d f4 2b 0d 90 01 04 8b 55 0c 88 04 0a 90 00 } //01 00 
		$a_81_1 = {64 2b 25 37 46 4d 38 4d 55 65 53 48 30 5f 78 48 34 29 4c 71 46 6c 36 44 5e 44 37 77 73 71 6b 34 4a 78 69 50 71 30 56 6d 40 24 3f 38 6d 4d 26 53 6a 43 3c 58 51 39 66 37 4c 74 2b 4b 62 3e 53 52 4a 51 39 } //00 00  d+%7FM8MUeSH0_xH4)LqFl6D^D7wsqk4JxiPq0Vm@$?8mM&SjC<XQ9f7Lt+Kb>SRJQ9
	condition:
		any of ($a_*)
 
}