
rule Trojan_Win32_Trickbot_AK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c1 f7 75 0c 8a 5c 0c 50 0f b6 c3 41 0f b6 14 3a 03 d6 03 c2 33 d2 be e2 90 01 03 f7 f6 8b f2 8a 44 34 50 88 44 0c 4f 88 5c 34 50 81 f9 e2 90 1b 00 72 ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_AK_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {2f 25 73 2f 25 73 2f 35 2f 25 73 2f } //01 00 
		$a_81_1 = {2f 35 2f 73 70 6b 2f } //01 00 
		$a_81_2 = {70 77 67 72 61 62 } //01 00 
		$a_81_3 = {6d 63 63 6f 6e 66 } //01 00 
		$a_81_4 = {61 75 74 6f 72 75 6e } //01 00 
		$a_81_5 = {2f 73 72 76 } //01 00 
		$a_81_6 = {31 38 36 2e 37 31 2e 31 35 30 2e 32 33 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_AK_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.AK!MTB!!Trickbot.AK!MTB,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {70 77 67 72 61 62 } //01 00 
		$a_81_1 = {2f 25 73 2f 25 73 2f 35 2f 25 73 2f } //01 00 
		$a_81_2 = {2f 35 2f 73 70 6b 2f } //01 00 
		$a_81_3 = {6d 63 63 6f 6e 66 } //01 00 
		$a_81_4 = {61 75 74 6f 72 75 6e } //01 00 
		$a_81_5 = {31 38 36 2e 37 31 2e 31 35 30 2e 32 33 } //00 00 
	condition:
		any of ($a_*)
 
}