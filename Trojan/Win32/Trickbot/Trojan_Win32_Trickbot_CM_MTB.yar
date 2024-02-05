
rule Trojan_Win32_Trickbot_CM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {32 5c 64 6c 6c 5c 52 65 6c 65 61 73 65 5c 54 65 73 74 30 31 2e 70 64 62 } //01 00 
		$a_81_1 = {31 2e 64 6c 6c } //01 00 
		$a_81_2 = {44 70 69 38 30 30 } //01 00 
		$a_81_3 = {47 65 74 4d 6f 75 73 65 } //01 00 
		$a_81_4 = {5b 20 47 4f 4f 44 20 5d } //01 00 
		$a_03_5 = {6a 40 68 00 10 00 00 90 02 06 6a 00 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_CM_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 3c 0b 33 d2 88 0c 38 8b c1 f7 74 24 90 01 01 8b 44 24 90 01 01 41 8a 14 02 88 17 8b 3d 90 01 04 3b cf 72 90 00 } //01 00 
		$a_03_1 = {8a 19 0f be 14 08 8b c3 03 f2 25 ff 00 00 00 33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 15 90 02 12 03 c2 8b 15 90 01 04 03 c2 8d 14 90 01 01 8b c6 2b c2 88 1c 28 8b 44 24 90 01 01 8b 3d 90 01 04 40 41 3b c7 89 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}