
rule Trojan_Win32_Trickbot_PB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 72 39 6a 6e 58 79 35 52 23 4b 7b 71 7a 6b } //01 00 
		$a_00_1 = {64 75 7a 24 45 23 6b 51 25 65 74 49 71 30 46 2a 39 55 4e 76 48 66 46 72 4d 51 } //01 00 
		$a_02_2 = {8a 00 88 c1 8b 45 90 01 01 8b 9c 90 01 05 8b 45 90 01 01 8b 84 90 01 05 01 d8 25 ff 00 00 80 85 c0 79 90 01 01 48 0d 00 ff ff ff 40 8b 84 90 01 05 31 c8 88 02 ff 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 92 c0 84 c0 0f 85 90 00 } //00 00 
		$a_00_3 = {78 98 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_PB_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 c7 45 90 01 01 00 00 00 00 eb 90 01 01 8b 45 90 01 01 83 c0 01 89 45 90 01 01 8b 4d 90 01 01 3b 4d 90 01 01 74 90 01 01 8b 45 90 01 01 33 d2 b9 90 01 04 f7 f1 8b 45 90 01 01 03 45 90 01 01 8b 4d 90 01 01 8a 00 32 04 11 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb 90 00 } //01 00 
		$a_02_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 90 02 40 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}