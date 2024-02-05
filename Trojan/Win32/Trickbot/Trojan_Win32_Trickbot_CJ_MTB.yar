
rule Trojan_Win32_Trickbot_CJ_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 67 66 68 67 64 68 67 64 68 33 } //01 00 
		$a_81_1 = {77 69 6e 70 65 2e 65 78 65 } //01 00 
		$a_81_2 = {68 67 66 68 67 64 68 67 64 68 31 } //01 00 
		$a_81_3 = {29 6a 51 58 3f 30 4b 6d 23 6b 4f 30 72 61 47 24 40 63 24 26 41 50 56 44 3c 52 4f 4f 53 72 31 68 6a 24 43 43 44 40 6c 32 23 66 59 3c 3e 65 35 3f 43 4e 61 44 } //01 00 
		$a_81_4 = {30 30 33 77 6e 74 63 7a 4d 47 63 6c 46 48 78 21 42 23 6b 4d 69 2b 69 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_CJ_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 90 01 01 8a 4d 90 01 01 88 08 8b 45 90 01 01 33 d2 f7 75 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 4d 90 01 01 8a 14 11 88 10 90 00 } //01 00 
		$a_03_1 = {03 d0 8b 0d 90 01 04 0f af 0d 90 01 04 03 d1 a1 90 01 04 0f af 05 90 01 04 03 d0 8b 0d 90 01 04 0f af 0d 90 01 04 03 d1 a1 90 01 04 0f af 05 90 01 04 03 d0 8b 0d 90 01 04 0f af 0d 90 01 04 03 4d 08 8a 45 fc 88 04 11 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}